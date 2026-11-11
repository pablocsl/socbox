#!/usr/bin/env python3
import base64, getpass, hashlib, ipaddress, json, math, os, platform, re
import secrets, socket, ssl, stat, string, subprocess, sys, urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psutil
import questionary
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dotenv import load_dotenv

load_dotenv()

console = Console()
TIMEOUT = 15
MAGIC = b"SOCB1"

SYSTEM = platform.system()
IS_WIN, IS_MAC, IS_LINUX = SYSTEM == "Windows", SYSTEM == "Darwin", SYSTEM == "Linux"
OS_NAME = "macOS" if IS_MAC else SYSTEM


def first_existing(*paths):
    """Return the first path that exists, otherwise the first candidate."""
    return next((p for p in paths if os.path.exists(p)), paths[0])


if IS_WIN:
    DEFAULTS = {
        "auth_log": "",
        "web_log": first_existing(r"C:\xampp\apache\logs\access.log", r"C:\nginx\logs\access.log"),
        "audit_dir": r"C:\Windows\System32\drivers\etc",
        "fim_dir": r"C:\Windows\System32\drivers\etc",
    }
elif IS_MAC:
    DEFAULTS = {
        "auth_log": "/var/log/system.log",
        "web_log": first_existing("/var/log/apache2/access_log", "/opt/homebrew/var/log/nginx/access.log"),
        "audit_dir": "/etc",
        "fim_dir": "/etc",
    }
else:
    DEFAULTS = {
        "auth_log": first_existing("/var/log/auth.log", "/var/log/secure"),
        "web_log": first_existing("/var/log/nginx/access.log", "/var/log/apache2/access.log",
                                  "/var/log/httpd/access_log"),
        "audit_dir": "/etc",
        "fim_dir": "/etc",
    }


def is_admin():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def run_ps(cmd, timeout=90):
    """Run a PowerShell command. Returns (stdout, error)."""
    try:
        prefix = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", prefix + cmd],
                           capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    return (r.stdout, "") if r.returncode == 0 else (None, r.stderr.strip() or "PowerShell error")


def ps_json(cmd):
    """Run PowerShell and parse the output as a list of JSON objects."""
    out, err = run_ps(f"{cmd} | ConvertTo-Json -Compress -Depth 3")
    if out is None:
        return None, err
    out = out.strip()
    if not out:
        return [], ""
    try:
        data = json.loads(out)
    except ValueError:
        return None, "Could not parse PowerShell output"
    return (data if isinstance(data, list) else [data]), ""


def ask(msg, default=""):
    return (questionary.text(msg, default=default).ask() or "").strip()


def key(name):
    k = os.environ.get(name)
    if not k:
        console.print(f"[yellow]Missing environment variable {name}.[/]")
    return k


def http_get(url, **kw):
    try:
        return requests.get(url, timeout=TIMEOUT, **kw)
    except requests.RequestException as e:
        console.print(f"[red]Network error:[/] {e}")
        return None


def kv_table(title, rows):
    t = Table(title=title, show_header=False, border_style="cyan")
    t.add_column(style="bold cyan")
    t.add_column()
    for k, v in rows:
        t.add_row(str(k), str(v))
    console.print(t)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def t_hash():
    mode = questionary.select("Source", choices=["File", "Text"]).ask()
    if not mode:
        return
    if mode == "File":
        path = ask("File path:")
        if not os.path.isfile(path):
            return console.print("[red]File not found[/]")
        hs = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                for h in hs.values():
                    h.update(chunk)
    else:
        data = ask("Text:").encode()
        hs = {n: hashlib.new(n, data) for n in ("md5", "sha1", "sha256")}
    kv_table("Hashes", [(n.upper(), h.hexdigest()) for n, h in hs.items()])


def _derive(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def t_encrypt():
    path = ask("File to encrypt:")
    if not os.path.isfile(path):
        return console.print("[red]File not found[/]")
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat password: "):
        return console.print("[red]Passwords do not match[/]")
    salt, nonce = os.urandom(16), os.urandom(12)
    with open(path, "rb") as f:
        ct = AESGCM(_derive(pw, salt)).encrypt(nonce, f.read(), MAGIC)
    out = path + ".socb"
    with open(out, "wb") as f:
        f.write(MAGIC + salt + nonce + ct)
    console.print(f"[green]Encrypted (AES-256-GCM + scrypt):[/] {out}")


def t_decrypt():
    path = ask(".socb file:")
    if not os.path.isfile(path):
        return console.print("[red]File not found[/]")
    blob = open(path, "rb").read()
    if not blob.startswith(MAGIC):
        return console.print("[red]Unrecognized format[/]")
    salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
    try:
        pt = AESGCM(_derive(getpass.getpass("Password: "), salt)).decrypt(nonce, ct, MAGIC)
    except Exception:
        return console.print("[red]Wrong password or tampered file[/]")
    out = path[:-5] if path.endswith(".socb") else path + ".dec"
    with open(out, "wb") as f:
        f.write(pt)
    console.print(f"[green]Decrypted:[/] {out}")


def t_password_gen():
    n = int(ask("Length:", "20") or 20)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    pw = "".join(secrets.choice(alphabet) for _ in range(n))
    kv_table("Password", [("Generated", pw), ("Approx. entropy", f"{n * math.log2(len(alphabet)):.0f} bits")])


COMMON_PW = {"password", "contraseña", "root", "123456", "123456789", "qwerty", "admin", "letmein", "welcome",
             "iloveyou", "abc123", "monkey", "dragon", "football", "login", "passw0rd", "contraseña123", "password123"}


def audit_password(pw):
    pool = sum(n for cond, n in [(re.search(r"[a-z]", pw), 26), (re.search(r"[A-Z]", pw), 26),
                                 (re.search(r"\d", pw), 10), (re.search(r"[^\w]", pw), 32)] if cond)
    entropy = len(pw) * math.log2(pool) if pool else 0
    issues = []
    if len(pw) < 12:
        issues.append("shorter than 12 characters")
    if pw.lower() in COMMON_PW or any(c in pw.lower() for c in COMMON_PW if len(c) >= 6):
        issues.append("contains a very common password")
    if re.search(r"(.)\1{2,}", pw):
        issues.append("repeated characters (aaa)")
    if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)", pw.lower()):
        issues.append("keyboard/number sequence")
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        issues.append("mixes fewer than 3 character classes")
    rating = "Weak" if entropy < 50 or len(issues) >= 3 else "Medium" if entropy < 70 or issues else "Strong"
    return entropy, issues, rating


def t_password_audit():
    pw = getpass.getpass("Password to audit (hidden): ")
    if not pw:
        return
    entropy, issues, rating = audit_password(pw)
    color = {"Weak": "red", "Medium": "yellow", "Strong": "green"}[rating]
    kv_table("Password audit", [("Length", len(pw)), ("Entropy", f"{entropy:.0f} bits"),
                                ("Rating", f"[{color}]{rating}[/]"),
                                ("Issues", "; ".join(issues) or "none found")])
    if questionary.confirm("Check Have I Been Pwned? (only the first 5 chars of the SHA-1 are sent)",
                           default=True).ask():
        sha = hashlib.sha1(pw.encode()).hexdigest().upper()
        r = http_get(f"https://api.pwnedpasswords.com/range/{sha[:5]}")
        if r is not None and r.ok:
            hits = {l.split(":")[0]: int(l.split(":")[1]) for l in r.text.splitlines()}
            n = hits.get(sha[5:], 0)
            console.print(f"[red]Found in {n:,} breaches - do not use it.[/]" if n
                          else "[green]Not found in known breaches.[/]")


def t_decode():
    s = ask("String to decode:")
    rows = []
    for name, fn in [
        ("Base64", lambda x: base64.b64decode(x + "=" * (-len(x) % 4)).decode(errors="replace")),
        ("Base64 URL", lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).decode(errors="replace")),
        ("Hex", lambda x: bytes.fromhex(x).decode(errors="replace")),
        ("URL", urllib.parse.unquote),
        ("ROT13", lambda x: x.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))),
    ]:
        try:
            rows.append((name, fn(s)))
        except Exception:
            rows.append((name, "[dim]invalid[/]"))
    kv_table("Decoder", rows)


IOC_RE = {
    "IPv4": r"\b(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}\b",
    "URL": r"\bhxxps?://[^\s\"'<>]+|\bhttps?://[^\s\"'<>]+",
    "Email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
    "SHA256": r"\b[a-fA-F0-9]{64}\b",
    "SHA1": r"\b[a-fA-F0-9]{40}\b",
    "MD5": r"\b[a-fA-F0-9]{32}\b",
    "Domain": r"\b(?:[a-z0-9-]+(?:\[?\.\]?))+(?:com|net|org|io|ru|cn|info|biz|xyz|top|es|de|uk|gov|edu)\b",
}


def t_ioc():
    print("Paste your text and finish with an empty line:")
    lines = []
    while (l := sys.stdin.readline()) and l.strip():
        lines.append(l)
    text = "".join(lines)
    refang = lambda x: x.replace("[.]", ".").replace("hxxp", "http")
    t = Table(title="IOCs found", border_style="cyan")
    t.add_column("Type", style="bold")
    t.add_column("Value (refanged)")
    seen = set()
    for kind, rx in IOC_RE.items():
        for m in re.findall(rx, text, re.I):
            v = refang(m)
            if v not in seen:
                seen.add(v)
                t.add_row(kind, v)
    console.print(t if seen else "[yellow]No IOCs found[/]")


def t_defang():
    s = ask("Value:")
    kv_table("Defang / Refang", [("Defanged", s.replace("http", "hxxp").replace(".", "[.]")),
                                 ("Refanged", s.replace("[.]", ".").replace("hxxp", "http"))])


def t_ssh_log():
    path = ask("Auth log path:", DEFAULTS["auth_log"])
    if not os.path.isfile(path):
        return console.print("[red]File not found[/]")
    rx = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    ips, users = Counter(), Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if m := rx.search(line):
                users[m[1]] += 1
                ips[m[2]] += 1
    t = Table(title="Failed SSH logins", border_style="red")
    t.add_column("Source IP")
    t.add_column("Attempts", justify="right")
    for ip, n in ips.most_common(10):
        t.add_row(ip, str(n))
    console.print(t)
    console.print("Most targeted users:", ", ".join(f"{u} ({n})" for u, n in users.most_common(5)) or "-")


SUSPICIOUS = {
    "Path traversal": r"\.\./|%2e%2e",
    "SQL injection": r"union(?:%20|\+| )+select|or(?:%20|\+| )+1=1|sleep\(\d+\)",
    "XSS": r"<script|%3cscript|onerror=",
    "Admin/CMS probing": r"wp-login|xmlrpc\.php|/\.env|phpmyadmin|/\.git/",
    "Command injection": r"(?:;|%3b|\|)(?:%20|\+| )*(?:cat|wget|curl|bash|sh)\b",
}


def t_web_log():
    path = ask("Web access log (Apache/Nginx):", DEFAULTS["web_log"])
    if not os.path.isfile(path):
        return console.print("[red]File not found[/]")
    rx = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3})')
    ips, status, hits = Counter(), Counter(), {k: Counter() for k in SUSPICIOUS}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = rx.match(line)
            if not m:
                continue
            ip, _, url, code = m.groups()
            ips[ip] += 1
            status[code[0] + "xx"] += 1
            for name, pat in SUSPICIOUS.items():
                if re.search(pat, url, re.I):
                    hits[name][ip] += 1
    kv_table("Status classes", sorted(status.items()))
    t = Table(title="Top clients", border_style="cyan")
    t.add_column("IP")
    t.add_column("Requests", justify="right")
    for ip, n in ips.most_common(10):
        t.add_row(ip, str(n))
    console.print(t)
    for name, c in hits.items():
        if c:
            console.print(f"[red]{name}:[/] " + ", ".join(f"{ip} ({n})" for ip, n in c.most_common(5)))


def t_fim():
    mode = questionary.select("Mode", choices=["Create baseline", "Verify against baseline"]).ask()
    if not mode:
        return
    root = ask("Directory:", DEFAULTS["fim_dir"])
    base = ask("Baseline file:", "baseline.json")
    current = {}
    for dp, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dp, fn)
            if os.path.abspath(p) == os.path.abspath(base) or os.path.islink(p):
                continue
            try:
                current[p] = {"sha256": sha256_file(p), "size": os.path.getsize(p)}
            except OSError:
                continue
    if mode == "Create baseline":
        with open(base, "w") as f:
            json.dump({"created": datetime.now().isoformat(), "files": current}, f, indent=1)
        return console.print(f"[green]Baseline saved:[/] {len(current)} files -> {base}")
    if not os.path.isfile(base):
        return console.print("[red]Baseline not found[/]")
    old = json.load(open(base))["files"]
    modified = [p for p in current if p in old and current[p]["sha256"] != old[p]["sha256"]]
    new = [p for p in current if p not in old]
    deleted = [p for p in old if p not in current]
    for label, items, color in [("Modified", modified, "red"), ("New", new, "yellow"), ("Deleted", deleted, "magenta")]:
        console.print(f"[{color}]{label}: {len(items)}[/]")
        for p in items[:30]:
            console.print("  ", p)
    if not (modified or new or deleted):
        console.print("[green]Integrity OK - no changes detected.[/]")


LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "10": "RemoteInteractive (RDP)", "11": "CachedInteractive"}


def t_win_failed_logons():
    n = int(ask("Max events to read:", "2000") or 2000)
    cmd = ("Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents %d -ErrorAction Stop | "
           "ForEach-Object { $d=@{}; ([xml]$_.ToXml()).Event.EventData.Data | "
           "ForEach-Object { $d[$_.Name]=$_.'#text' }; "
           "[pscustomobject]@{User=$d['TargetUserName'];IP=$d['IpAddress'];Type=$d['LogonType']} }") % n
    events, err = ps_json(cmd)
    if events is None:
        if any(k in err for k in ("NoMatchingEventsFound", "No events were found", "No se encontraron")):
            return console.print("[green]No failed logon events (4625) found.[/]")
        if not is_admin() or any(k in err for k in ("LogInfoUnavailable", "UnauthorizedAccess")):
            return console.print("[red]Cannot read the Security log. Close this window and run the terminal "
                                 "as Administrator (right-click > Run as administrator).[/]")
        return console.print(f"[red]Could not read the Security log:[/] {err[:300]}")
    ips = Counter(e["IP"] for e in events if e.get("IP") not in (None, "", "-", "::1", "127.0.0.1"))
    users = Counter(e.get("User") for e in events)
    types = Counter(LOGON_TYPES.get(str(e.get("Type")), str(e.get("Type"))) for e in events)
    console.print(f"[bold]{len(events)} failed logons analyzed[/]")
    t = Table(title="Top source IPs", border_style="red")
    t.add_column("IP")
    t.add_column("Attempts", justify="right")
    for ip, c in ips.most_common(10):
        t.add_row(ip, str(c))
    console.print(t)
    console.print("Most targeted accounts:", ", ".join(f"{u} ({c})" for u, c in users.most_common(5)) or "-")
    console.print("Logon types:", ", ".join(f"{k} ({v})" for k, v in types.most_common()) or "-")


def t_win_audit():
    console.print("[dim]Collecting data with PowerShell (may take a few seconds)...[/]")

    def show(title, cmd, cols):
        data, err = ps_json(cmd)
        if data is None:
            return console.print(f"[yellow]{title}: unavailable ({err[:80]})[/]")
        t = Table(title=title, border_style="cyan")
        for c in cols:
            t.add_column(c)
        for row in data[:25]:
            t.add_row(*[str(row.get(c, "")) for c in cols])
        console.print(t if data else f"[green]{title}: none[/]")

    d, _ = ps_json("Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled,"
                   "AntivirusSignatureLastUpdated")
    if d:
        ok = lambda v: "[green]enabled[/]" if v else "[red]DISABLED[/]"
        kv_table("Microsoft Defender", [("Antivirus", ok(d[0].get("AntivirusEnabled"))),
                                        ("Real-time protection", ok(d[0].get("RealTimeProtectionEnabled")))])
    else:
        console.print("[yellow]Defender status unavailable (third-party AV or missing privileges).[/]")
    fw, _ = ps_json("Get-NetFirewallProfile | Select Name,Enabled")
    if fw:
        kv_table("Windows Firewall", [(f["Name"], "[green]enabled[/]" if f["Enabled"] in (True, 1, "True")
                                       else "[red]DISABLED[/]") for f in fw])
    out, _ = run_ps(r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections")
    if out is not None and out.strip():
        kv_table("Remote Desktop", [("RDP", "[yellow]ENABLED[/]" if out.strip() == "0" else "[green]disabled[/]")])
    show("Local administrators", "Get-LocalGroupMember -SID S-1-5-32-544 | Select Name,PrincipalSource",
         ["Name", "PrincipalSource"])
    show("Startup programs", "Get-CimInstance Win32_StartupCommand | Select Name,Command,Location",
         ["Name", "Command"])
    show("Non-Microsoft scheduled tasks",
         r"Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } "
         "| Select TaskName,TaskPath", ["TaskName", "TaskPath"])
    show("Running services outside standard paths",
         "Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -and "
         "$_.PathName -notmatch 'system32|syswow64|Program Files|Windows Defender' } | Select Name,PathName",
         ["Name", "PathName"])


def t_sysinfo():
    vm, disk = psutil.virtual_memory(), psutil.disk_usage(os.path.abspath(os.sep))
    boot = datetime.fromtimestamp(psutil.boot_time())
    kv_table("System information", [
        ("Hostname", socket.gethostname()), ("Privileges", "Administrator/root" if is_admin() else "Standard user"), ("OS", platform.platform()), ("Architecture", platform.machine()),
        ("CPU cores", f"{psutil.cpu_count()} ({psutil.cpu_percent(interval=0.5)}% in use)"),
        ("RAM", f"{human(vm.used)} / {human(vm.total)} ({vm.percent}%)"),
        ("Disk", f"{human(disk.used)} / {human(disk.total)} ({disk.percent}%)"),
        ("Boot time", f"{boot:%Y-%m-%d %H:%M}"),
        ("Logged-in users", ", ".join({u.name for u in psutil.users()}) or "-")])
    t = Table(title="Listening ports", border_style="cyan")
    for c in ("Port", "Address", "PID", "Process"):
        t.add_column(c)
    try:
        for c in sorted((c for c in psutil.net_connections("inet") if c.status == "LISTEN"),
                        key=lambda c: c.laddr.port):
            try:
                name = psutil.Process(c.pid).name() if c.pid else "-"
            except psutil.Error:
                name = "-"
            t.add_row(str(c.laddr.port), c.laddr.ip, str(c.pid or "-"), name)
        console.print(t)
    except psutil.AccessDenied:
        console.print("[yellow]Run with elevated privileges to list listening ports.[/]")
    procs = sorted(psutil.process_iter(["pid", "name", "memory_percent"]),
                   key=lambda p: p.info["memory_percent"] or 0, reverse=True)[:5]
    kv_table("Top processes by memory", [(f"{p.info['name']} ({p.info['pid']})",
                                          f"{p.info['memory_percent'] or 0:.1f}%") for p in procs])


def t_fs_audit():
    root = ask("Directory to audit:", DEFAULTS["audit_dir"])
    ww, suid = [], []
    for dp, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dp, fn)
            try:
                m = os.lstat(p).st_mode
            except OSError:
                continue
            if stat.S_ISLNK(m):
                continue
            if m & stat.S_IWOTH:
                ww.append(p)
            if m & stat.S_ISUID:
                suid.append(p)
    console.print(f"[bold]World-writable files:[/] {len(ww)}")
    for p in ww[:30]:
        console.print("  ", p)
    console.print(f"[bold]SUID binaries:[/] {len(suid)}")
    for p in suid[:30]:
        console.print("  ", p)


def t_portscan():
    host = ask("Host (authorized targets only):", "127.0.0.1")
    if not questionary.confirm(f"Are you authorized to scan {host}?", default=False).ask():
        return
    rng = ask("Ports (e.g. 1-1024 or 22,80,443):", "1-1024")
    ports = []
    for part in rng.split(","):
        a, _, b = part.partition("-")
        ports += range(int(a), int(b or a) + 1)

    def probe(p):
        with socket.socket() as s:
            s.settimeout(0.6)
            return p if s.connect_ex((host, p)) == 0 else None

    with ThreadPoolExecutor(200) as ex:
        open_ports = sorted(p for p in ex.map(probe, ports) if p)
    for p in open_ports:
        try:
            svc = socket.getservbyport(p)
        except OSError:
            svc = "?"
        console.print(f"[green]{p}/tcp open[/] ({svc})")
    if not open_ports:
        console.print("[yellow]No open ports in range[/]")


def t_dns():
    host = ask("Domain or IP:")
    try:
        if re.fullmatch(r"[\d.]+", host):
            kv_table("Reverse DNS", [("Hostname", socket.gethostbyaddr(host)[0])])
        else:
            _, _, ips = socket.gethostbyname_ex(host)
            kv_table("DNS", [("IPs", ", ".join(ips))])
    except OSError as e:
        console.print(f"[red]{e}[/]")


def t_subbrute():
    dom = ask("Domain (authorized targets only):")
    words = ("www mail ftp smtp pop imap webmail admin portal vpn remote dev test staging stage api app "
             "blog shop store cdn static assets img media ns1 ns2 mx intranet git gitlab jenkins ci jira "
             "wiki support help status monitor grafana kibana db sql backup old new beta m mobile").split()

    def resolve(w):
        try:
            return f"{w}.{dom}", socket.gethostbyname(f"{w}.{dom}")
        except OSError:
            return None

    with ThreadPoolExecutor(50) as ex:
        found = [r for r in ex.map(resolve, words) if r]
    for name, ip in found:
        console.print(f"[green]{name}[/] -> {ip}")
    if not found:
        console.print("[yellow]No subdomains resolved[/]")


def t_whois():
    target = ask("Domain or IP:")
    try:
        ipaddress.ip_address(target)
        url = f"https://rdap.org/ip/{target}"
    except ValueError:
        url = f"https://rdap.org/domain/{target}"
    r = http_get(url)
    if r is None:
        return
    if r.status_code != 200:
        try:
            msg = r.json().get("error", "")
        except ValueError:
            msg = r.text[:100]
        return console.print(f"[red]RDAP HTTP {r.status_code}:[/] {msg}")
    d = r.json()
    rows = [("Name", d.get("ldhName") or d.get("name")), ("Handle", d.get("handle")),
            ("Status", ", ".join(d.get("status", []))), ("Country", d.get("country")),
            ("Range", f"{d['startAddress']} - {d['endAddress']}" if "startAddress" in d else None),
            ("Nameservers", ", ".join(n["ldhName"] for n in d.get("nameservers", [])) or None)]
    for e in d.get("events", []):
        rows.append((e["eventAction"].title(), e["eventDate"][:10]))
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    rows.append(("Registrar", item[3]))
    kv_table("WHOIS (RDAP)", [(k, v) for k, v in rows if v])


def t_headers():
    url = ask("URL:", "https://")
    r = http_get(url, allow_redirects=True)
    if r is None:
        return
    wanted = {"Strict-Transport-Security": "HSTS", "Content-Security-Policy": "CSP",
              "X-Frame-Options": "Anti-clickjacking", "X-Content-Type-Options": "nosniff",
              "Referrer-Policy": "Referrer", "Permissions-Policy": "Permissions"}
    t = Table(title=f"Security headers - {r.url}", border_style="cyan")
    t.add_column("Header")
    t.add_column("Status")
    for h, desc in wanted.items():
        t.add_row(f"{h} ({desc})", "[green]present[/]" if h in r.headers else "[red]missing[/]")
    console.print(t)
    if "Server" in r.headers:
        console.print(f"Server: {r.headers['Server']}")


def t_tls():
    host = ask("Host:")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert, ver, cipher = ss.getpeercert(), ss.version(), ss.cipher()[0]
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        subj = dict(x[0] for x in cert["subject"])
        iss = dict(x[0] for x in cert["issuer"])
        kv_table("TLS certificate", [
            ("CN", subj.get("commonName")), ("Issuer", iss.get("organizationName")),
            ("Expires", f"{exp:%Y-%m-%d} ({days} days)"), ("Protocol", ver), ("Cipher", cipher)])
    except Exception as e:
        console.print(f"[red]TLS failure:[/] {e}")


def t_crtsh():
    dom = ask("Domain:")
    r = http_get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"})
    if r is None:
        return
    if r.status_code != 200:
        try:
            msg = r.json().get("error", "")
        except ValueError:
            msg = r.text[:100]
        return console.print(f"[red]crt.sh HTTP {r.status_code}:[/] {msg}")
    names = sorted({n for e in r.json() for n in e["name_value"].split("\n") if "*" not in n})
    console.print(f"[bold]{len(names)} subdomains found in certificates:[/]")
    for n in names[:80]:
        console.print("  ", n)


def _vt(path):
    k = key("VT_API_KEY")
    if not k:
        return None
    r = http_get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": k})
    if r is None:
        return None
    if r.status_code == 404:
        console.print("[yellow]VirusTotal has no data on this item[/]")
        return None
    if r.status_code != 200:
        console.print(f"[red]VT HTTP {r.status_code}[/]")
        return None
    return r.json()["data"]["attributes"]


def t_vt():
    kind = questionary.select("Type", choices=["File", "URL", "IP", "Domain", "Hash"]).ask()
    if not kind:
        return
    if kind == "File":
        return t_vt_file()
    val = ask(f"{kind}:")
    path = {"URL": "urls/" + base64.urlsafe_b64encode(val.encode()).decode().strip("="),
            "IP": f"ip_addresses/{val}", "Domain": f"domains/{val}",
            "Hash": f"files/{val}"}[kind]
    a = _vt(path)
    if not a:
        return
    rows = list(a.get("last_analysis_stats", {}).items())
    for extra in ("meaningful_name", "type_description", "reputation", "country", "as_owner"):
        if extra in a:
            rows.append((extra, a[extra]))
    kv_table("VirusTotal", rows)
    bad = [e for e, r in a.get("last_analysis_results", {}).items() if r["category"] in ("malicious", "suspicious")]
    if bad:
        console.print("[red]Flagged by:[/]", ", ".join(bad[:15]))


def _vt_verdict(stats, results, extra=()):
    kv_table("VirusTotal", list(stats.items()) + list(extra))
    bad = [e for e, r in results.items() if r["category"] in ("malicious", "suspicious")]
    if stats.get("malicious", 0) > 0:
        console.print(f"[bold red]MALICIOUS - flagged by {stats['malicious']} engines[/]")
    elif stats.get("suspicious", 0) > 0:
        console.print("[bold yellow]SUSPICIOUS - review manually[/]")
    else:
        console.print("[bold green]No engine flagged this file[/]")
    if bad:
        console.print("[red]Flagged by:[/]", ", ".join(bad[:15]))


def t_vt_file():
    path = ask("File to scan:")
    if not os.path.isfile(path):
        return console.print("[red]File not found[/]")
    k = key("VT_API_KEY")
    if not k:
        return
    headers = {"x-apikey": k}
    sha = sha256_file(path)
    console.print(f"SHA-256: {sha}")

    r = http_get(f"https://www.virustotal.com/api/v3/files/{sha}", headers=headers)
    if r is None:
        return
    if r.status_code == 200:
        a = r.json()["data"]["attributes"]
        console.print("[green]Already known to VirusTotal - no upload needed.[/]")
        return _vt_verdict(a.get("last_analysis_stats", {}), a.get("last_analysis_results", {}),
                           [(x, a[x]) for x in ("meaningful_name", "type_description") if x in a])
    if r.status_code != 404:
        return console.print(f"[red]VT HTTP {r.status_code}[/]")

    if os.path.getsize(path) > 32 * 1024 * 1024:
        return console.print("[yellow]File is over 32 MB; the simple upload endpoint does not accept it.[/]")
    if not questionary.confirm("VirusTotal does not know this file. Uploading shares it with VT and its "
                               "security community. Do NOT upload confidential files. Upload?",
                               default=False).ask():
        return
    try:
        with open(path, "rb") as f:
            up = requests.post("https://www.virustotal.com/api/v3/files", headers=headers,
                               files={"file": (os.path.basename(path), f)}, timeout=120)
    except requests.RequestException as e:
        return console.print(f"[red]Upload failed:[/] {e}")
    if up.status_code != 200:
        return console.print(f"[red]Upload failed (HTTP {up.status_code})[/]")
    aid = up.json()["data"]["id"]

    with console.status("Waiting for VirusTotal analysis..."):
        for _ in range(18):
            time.sleep(10)
            ar = http_get(f"https://www.virustotal.com/api/v3/analyses/{aid}", headers=headers)
            if ar is not None and ar.status_code == 200:
                attrs = ar.json()["data"]["attributes"]
                if attrs.get("status") == "completed":
                    return _vt_verdict(attrs["stats"], attrs.get("results", {}))
    console.print(f"[yellow]Analysis is still running. Check later:[/] https://www.virustotal.com/gui/file/{sha}")


def t_shodan():
    k = key("SHODAN_API_KEY")
    if not k:
        return
    ip = ask("IP:")
    r = http_get(f"https://api.shodan.io/host/{ip}", params={"key": k})
    if r is None:
        return
    if r.status_code != 200:
        try:
            msg = r.json().get("error", "")
        except ValueError:
            msg = r.text[:100]
        return console.print(f"[red]Shodan HTTP {r.status_code}:[/] {msg}")
    d = r.json()
    kv_table("Shodan", [("Org", d.get("org")), ("Country", d.get("country_name")), ("OS", d.get("os")),
                        ("Hostnames", ", ".join(d.get("hostnames", []))),
                        ("Ports", ", ".join(map(str, d.get("ports", [])))),
                        ("Vulns", ", ".join(d.get("vulns", [])) or "-")])


def t_abuse():
    k = key("ABUSEIPDB_API_KEY")
    if not k:
        return
    ip = ask("IP:")
    r = http_get("https://api.abuseipdb.com/api/v2/check", headers={"Key": k, "Accept": "application/json"},
                 params={"ipAddress": ip, "maxAgeInDays": 90})
    if r is None:
        return
    if r.status_code != 200:
        try:
            msg = r.json().get("error", "")
        except ValueError:
            msg = r.text[:100]
        return console.print(f"[red]AbuseIPDB {r.status_code}:[/] {msg}")
    d = r.json()["data"]
    kv_table("AbuseIPDB", [("Abuse score", f"{d['abuseConfidenceScore']}%"), ("Reports", d["totalReports"]),
                           ("Country", d["countryCode"]), ("ISP", d["isp"]), ("Usage", d["usageType"]),
                           ("Last reported", d["lastReportedAt"])])


def t_ipinfo():
    ip = ask("IP (empty = yours):")
    r = http_get(f"https://ipinfo.io/{ip}/json")
    if r is not None and r.ok:
        kv_table("IPInfo", list(r.json().items()))


UNIX = ("Linux", "Darwin")
LINUX = ("Linux",)
WIN = ("Windows",)

MENU = {
    "🔐 Crypto & Hashes": [
        ("Hash file/text", t_hash, None), ("Encrypt file", t_encrypt, None),
        ("Decrypt file", t_decrypt, None), ("Password generator", t_password_gen, None),
        ("Password auditor (strength + breach check)", t_password_audit, None)],
    "🕵️  Analysis & DFIR": [
        ("Decoder (b64/hex/url/rot13)", t_decode, None), ("Extract IOCs from text", t_ioc, None),
        ("Defang / Refang", t_defang, None),
        ("SSH failed-login analyzer (auth.log)", t_ssh_log, LINUX),
        ("Windows failed-logon analyzer (Event 4625)", t_win_failed_logons, WIN),
        ("Web access log analyzer", t_web_log, None),
        ("File integrity checker (baseline)", t_fim, None)],
    "🛡️  Local Audit": [
        ("System information", t_sysinfo, None),
        ("Windows security audit (Defender, firewall, RDP, admins...)", t_win_audit, WIN),
        ("Permissions audit (world-writable / SUID)", t_fs_audit, UNIX),
        ("TCP port scanner", t_portscan, None), ("DNS lookup", t_dns, None),
        ("Subdomain brute-force (DNS)", t_subbrute, None)],
    "🌐 Web / Threat Intel": [
        ("VirusTotal", t_vt, None), ("Shodan", t_shodan, None),
        ("AbuseIPDB", t_abuse, None), ("WHOIS lookup (RDAP)", t_whois, None),
        ("HTTP security headers", t_headers, None), ("TLS certificate", t_tls, None),
        ("Subdomains", t_crtsh, None), ("IPInfo", t_ipinfo, None)],
}


def build_menu():
    """Keep only the tools that make sense on the detected operating system."""
    menu = {cat: [(l, f) for l, f, plats in items if plats is None or SYSTEM in plats]
            for cat, items in MENU.items()}
    return {cat: items for cat, items in menu.items() if items}


LOGO = {
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "B": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "],
    "X": ["██╗  ██╗", "╚██╗██╔╝", " ╚███╔╝ ", " ██╔██╗ ", "██╔╝ ██╗", "╚═╝  ╚═╝"],
}


def banner():
    rows = ["".join(LOGO[c][i].ljust(9) for c in "SOCBOX") for i in range(6)]
    shades = ["#00e5ff", "#00cfee", "#00b8dd", "#00a1cc", "#008abb", "#0073aa"]
    width = len(rows[0])
    text = Text("\n")
    for row, shade in zip(rows, shades):
        text.append(row + "\n", style=f"bold {shade}")
    text.append("\n")
    text.append("interactive security toolkit".center(width) + "\n", style="bold white")
    text.append("made by pablocsl".center(width), style="dim cyan")
    console.print(Panel(text, border_style="cyan", padding=(0, 2), expand=False))
    priv = "admin/root" if is_admin() else "standard user"
    console.print(f"[dim]Detected: {OS_NAME} {platform.release()} | {priv}")
    if not is_admin():
        console.print("[dim]Tip: some tools (event logs, listening ports) need elevated privileges.[/]")
    console.print()


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    menu = build_menu()
    banner()
    while True:
        cat = questionary.select("Category", choices=list(menu) + ["-- Exit --"]).ask()
        if cat in (None, "-- Exit --"):
            break
        while True:
            labels = [l for l, _ in menu[cat]] + ["-- Back --"]
            choice = questionary.select(cat, choices=labels).ask()
            if choice in (None, "-- Back --"):
                break
            try:
                dict(menu[cat])[choice]()
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled[/]")
            except Exception as e:
                console.print(f"[red]Unexpected error:[/] {e}")
            console.print()


if __name__ == "__main__":
    main()