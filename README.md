# SOCBox

**Interactive security toolkit for SOC analysts, made by [pablocsl](https://github.com/pablocsl).**

SOCBox is a cross-platform command-line tool with an interactive menu that groups the utilities a SOC analyst reaches for every day: hashing and encryption, IOC extraction, log analysis, local auditing and threat-intelligence lookups (VirusTotal, Shodan, AbuseIPDB...), all in a single place and without having to remember a dozen different commands.

```
███████╗  ██████╗  ██████╗ ██████╗   ██████╗ ██╗  ██╗
██╔════╝ ██╔═══██╗██╔════╝ ██╔══██╗ ██╔═══██╗╚██╗██╔╝
███████╗ ██║   ██║██║      ██████╔╝ ██║   ██║ ╚███╔╝
╚════██║ ██║   ██║██║      ██╔══██╗ ██║   ██║ ██╔██╗
███████║ ╚██████╔╝╚██████╗ ██████╔╝ ╚██████╔╝██╔╝ ██╗
╚══════╝  ╚═════╝  ╚═════╝ ╚═════╝   ╚═════╝ ╚═╝  ╚═╝
              interactive security toolkit
                    made by pablocsl
```

## Features

### 🔐 Crypto & Hashes
| Tool | Description |
|---|---|
| Hash file/text | MD5, SHA-1 and SHA-256 of a file or a string |
| Encrypt / Decrypt file | AES-256-GCM with a key derived from your password using scrypt. Tampered files are detected on decryption (`.socb` format) |
| Password generator | Cryptographically secure random passwords (`secrets`) with entropy estimate |
| Password auditor | Entropy, common-password and pattern checks, plus an optional [Have I Been Pwned](https://haveibeenpwned.com/Passwords) lookup using k-anonymity (only the first 5 characters of the SHA-1 hash leave your machine) |

### 🕵️ Analysis & DFIR
| Tool | Description |
|---|---|
| Decoder | Base64, Base64-URL, hex, URL-encoding and ROT13 in one shot |
| Extract IOCs | Pull IPs, URLs, domains, e-mails and hashes out of any pasted text, with automatic refang |
| Defang / Refang | Safely share indicators (`hxxp://evil[.]com`) and restore them |
| SSH failed-login analyzer | Top attacking IPs and targeted users from `auth.log` *(Linux)* |
| Windows failed-logon analyzer | Analyzes Security event **4625**: top source IPs, targeted accounts and logon types (RDP, network, interactive...) *(Windows)* |
| Web access log analyzer | Status codes, top clients and attack patterns (path traversal, SQLi, XSS, CMS probing, command injection) in Apache/Nginx logs |
| File integrity checker | Create a SHA-256 baseline of a directory and later detect modified, new and deleted files |

### 🛡️ Local Audit
| Tool | Description |
|---|---|
| System information | OS, CPU, RAM, disk, logged-in users, listening ports with their process and top processes |
| Windows security audit | Defender and firewall status, RDP, local administrators, startup programs, non-Microsoft scheduled tasks and services running outside standard paths *(Windows)* |
| Permissions audit | World-writable files and SUID binaries *(Linux / macOS)* |
| TCP port scanner | Multithreaded connect scan (asks for confirmation of authorization first) |
| DNS lookup | Forward and reverse resolution |
| Subdomain brute-force | Resolves a built-in list of common subdomain names |

### 🌐 Web / Threat Intel
| Tool | Description | API key |
|---|---|---|
| VirusTotal | Look up a **file** (scan), **URL**, **IP**, **domain** or **hash**. File scan checks the hash first and only uploads the file if VirusTotal does not know it and you confirm | `VT_API_KEY` |
| Shodan | Open ports, organization, OS and known vulnerabilities of an IP | `SHODAN_API_KEY` |
| AbuseIPDB | Abuse confidence score and report history of an IP | `ABUSEIPDB_API_KEY` |
| WHOIS lookup | Domain and IP registration data via RDAP | none |
| HTTP security headers | Checks HSTS, CSP, X-Frame-Options, etc. | none |
| TLS certificate | Issuer, expiry, protocol and cipher | none |
| Subdomains | Subdomain discovery from certificate transparency logs ([crt.sh](https://crt.sh)) | none |
| IPInfo | Geolocation and ownership of an IP | none |

## Operating system support

SOCBox detects your operating system at startup, shows only the tools that make sense for it and suggests sensible default paths (log locations, directories to audit...).

| | Windows | Linux | macOS |
|---|:---:|:---:|:---:|
| Crypto, hashes, passwords | ✅ | ✅ | ✅ |
| Threat intel / web tools | ✅ | ✅ | ✅ |
| Decoder, IOCs, integrity checker, web log analyzer | ✅ | ✅ | ✅ |
| System information, port scanner, DNS | ✅ | ✅ | ✅ |
| Windows failed-logon analyzer & security audit | ✅ | ❌ | ❌ |
| SSH failed-login analyzer | ❌ | ✅ | ❌ |
| Permissions audit (SUID / world-writable) | ❌ | ✅ | ✅ |

> **Windows tip:** run the terminal **as Administrator** to read the Security event log (Event 4625) and to list the process behind each listening port. Use [Windows Terminal](https://aka.ms/terminal) for the best rendering of the banner and icons.

## Requirements

- Python 3.9 or newer
- The packages in [`requirements.txt`](requirements.txt): `rich`, `questionary`, `requests`, `cryptography`, `psutil`, `python-dotenv`

## Installation

**Linux / macOS**
```bash
git clone https://github.com/pablocsl/socbox.git
cd socbox
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/pablocsl/socbox.git
cd socbox
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> If PowerShell blocks the activation script, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
> On Debian/Ubuntu you may need `sudo apt install python3-venv` first.

## Configuration

The online tools that need an API key read it from environment variables. The easiest way is to create a `.env` file in the project root (it is loaded automatically):

```env
VT_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

All keys are optional: tools without a configured key simply tell you what is missing, and everything else keeps working. Free tiers are enough for personal use, but they have rate limits.

Get your keys here:
- VirusTotal: <https://www.virustotal.com/gui/my-apikey>
- Shodan: <https://account.shodan.io>
- AbuseIPDB: <https://www.abuseipdb.com/account/api>

> ⚠️ **Never commit your `.env` file.** It is already listed in `.gitignore`. If you ever push it by mistake, regenerate the keys.

## Usage

```bash
python socbox.py
```

Navigate with the arrow keys, press Enter to select and use **`<- Back`** or `Ctrl+C` to cancel the current tool. To leave the virtual environment when you are done, run `deactivate`.

## Privacy and security notes

- **VirusTotal uploads are shared.** Files uploaded to VirusTotal become accessible to its security community. SOCBox looks up the hash first, only offers to upload unknown files, and asks for confirmation. **Never upload confidential files.** The simple upload endpoint is limited to 32 MB.
- **Password audit.** The password is typed with hidden input and never stored. The optional breach check uses k-anonymity: only a 5-character hash prefix is sent.
- **Encrypted files.** If you lose the password of a `.socb` file there is no way to recover it.
- **Scanning.** Only scan hosts and domains you own or are explicitly authorized to test.

## Project structure

```
socbox/
├── socbox.py          # The whole tool (menu, banner and all modules)
├── requirements.txt   # Python dependencies
├── .env               # Your API keys (not versioned)
└── .gitignore
```

## Adding your own tool

1. Write a function that takes no arguments and prints its results (use the `ask()`, `kv_table()` and `console` helpers).
2. Register it in the `MENU` dictionary with `(label, function, platforms)`. Use `None` for all systems, or `WIN`, `LINUX` or `UNIX` to restrict it:

```python
"🛡️  Local Audit": [
    ...
    ("My new tool", t_my_tool, None),
],
```

## Disclaimer

SOCBox is intended for defensive security work, education and authorized testing. You are solely responsible for how you use it. The author accepts no liability for misuse or damage.

## License

This project is licensed under the [MIT License](LICENSE).

---

By **pablocsl**