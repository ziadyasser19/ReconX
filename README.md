# RECONX — AI-Automated Reconnaissance and Enumeration Tool

>   
> **Author:** Ziad Khafaga  
>  

---

## What Is This Tool?

RECON is a Python command-line tool that automates the reconnaissance and enumeration phase of penetration testing. Instead of running five or six separate tools and combining the results by hand, this tool does everything in one run — scanning, fingerprinting, WAF detection, path analysis — and then uses an AI-style risk scoring engine to tell you what the most dangerous findings are and what to do about them.

It works on any domain or IP address you are **authorised to test**.

---

## Features

| Module | What It Does |
|---|---|
| Subdomain Enumeration | Brute-forces subdomains using DNS resolution with 30 parallel threads |
| Port Scanner | Checks 35 common TCP ports with service banner grabbing using 100 threads |
| Web Technology Detection | Fingerprints 17 technologies from HTTP headers and HTML body patterns |
| WAF Detection | Two-phase detection — passive header signatures + active payload testing across 12 vendors |
| Robots.txt & Sitemap Parser | Fetches and parses robots.txt and sitemap.xml, flags sensitive disclosed paths |
| Directory Enumeration | Brute-forces paths using external or built-in wordlists with 25 threads |
| AI Risk Scoring Engine | Scores all findings, maps to LOW / MEDIUM / HIGH / CRITICAL, generates recommendations |
| JSON Report | Saves full structured report to disk after every scan |

---

## Project Structure

```
recon/
│
├── recon_tool.py           ← Main tool (run this)
│
├── wordlists/
│   ├── subdomains.txt      ← Place your subdomain wordlist here
│   └── directories.txt     ← Place your directory wordlist here
│
├── requirements.txt        ← Python dependencies
├── .gitignore              ← Files to exclude from version control
└── README.md               ← This file
```

> Reports are saved automatically to the same folder where you run the tool:
> `report_<target>_<YYYYMMDD_HHMMSS>.json`

---

## Requirements

- Python 3.7 or higher
- pip
- Linux recommended (Kali Linux or Ubuntu) — works on Windows too

---

## Installation

### 1. Clone or download the project

```bash
git clone https://github.com/your-username/recon-tool.git
cd recon-tool
```

Or just download and extract the ZIP folder from Google Drive.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> On newer Linux systems (Ubuntu 23+, Kali 2024+) use:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

> **Note:** The tool also auto-installs missing dependencies when it first runs, so this step is optional.

---

## Wordlists (Optional but Recommended)

The tool has a small built-in wordlist as a fallback. For much better coverage, download these free wordlists from SecLists:

### Subdomains
```
https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-5000.txt
```
Save it as: `wordlists/subdomains.txt`

### Directories
```
https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```
Save it as: `wordlists/directories.txt`

### If you are on Kali Linux, SecLists is already installed:
```bash
sudo apt install seclists

cp /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt wordlists/subdomains.txt
cp /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt wordlists/directories.txt
```

---

## How to Run

```bash
python3 recon_tool.py
```

Then follow the prompts:

```
Enter target (domain / IP): testphp.vulnweb.com

+-- Scan Modules -----------------------------------------------+
|  [1] Full Scan   -- all modules                               |
|  [2] Quick Scan  -- ports + web tech + WAF                    |
|  [3] Recon Only  -- subdomains + robots/sitemap               |
|  [4] Web Audit   -- web tech + WAF + dirs + robots/sitemap    |
|  [5] Port Scan   -- port scan only                            |
|  [6] WAF Check   -- WAF detection only                        |
+---------------------------------------------------------------+

Select option [1-6]: 1
```

---

## Scan Modes

| Mode | Name | Modules Included |
|---|---|---|
| 1 | Full Scan | All six modules |
| 2 | Quick Scan | Port scan + Web tech + WAF |
| 3 | Recon Only | Subdomain enum + Robots/Sitemap |
| 4 | Web Audit | Web tech + WAF + Robots/Sitemap + Directory enum |
| 5 | Port Scan | Port scan only |
| 6 | WAF Check | WAF detection only |

---

## Example Output

```
  [+] Target resolved  ->  testphp.vulnweb.com  [44.228.249.3]

────────────────────────────────────────────────
  PORT SCAN -- 44.228.249.3
────────────────────────────────────────────────
  [+] Port 21     OPEN  [FTP]
  [+] Port 80     OPEN  [HTTP]
  [+] Port 443    OPEN  [HTTPS]

────────────────────────────────────────────────
  WAF DETECTION
────────────────────────────────────────────────
  [*] No WAF detected — target appears unprotected.

────────────────────────────────────────────────
  AI ANALYSIS & PRIORITIZATION ENGINE
────────────────────────────────────────────────
  [01] HIGH RISK: Port 21 open — FTP clear-text credentials
  [02] HIGH RISK: No WAF detected — application has no perimeter protection
  [03] HIGH RISK: Sensitive path accessible -> /admin [HTTP 200]

  [||||||||||||||......] CRITICAL (75/100)
```

---

## Authorised Test Targets

You can safely test this tool on these publicly authorised targets:

| Target | Purpose | Who Runs It |
|---|---|---|
| `testphp.vulnweb.com` | Intentionally vulnerable PHP app | Acunetix |
| `scanme.nmap.org` | Authorised port scan target | Nmap Project |
| `example.com` | Basic connectivity test | IANA |

---

## Ethical and Legal Warning

```
This tool is for authorised security testing only.
Scanning systems without explicit written permission
is illegal in most countries including Egypt (Law No. 175 of 2018).
The author is not responsible for any misuse of this tool.
```

---

## How the AI Engine Works

The risk scoring engine evaluates every finding and assigns a score:

| Finding | Score Added |
|---|---|
| Critical port open (FTP, RDP, MongoDB, Docker, etc.) | +20 per port |
| No WAF detected | +20 |
| Sensitive path in robots.txt | +10 per path |
| Missing security headers | +10 |
| Accessible sensitive directory (HTTP 200) | +25 per directory |
| Blocked sensitive directory (HTTP 403/401) | +10 per directory |
| Plain HTTP port open | +5 |

| Total Score | Risk Level |
|---|---|
| 0 – 14 | LOW |
| 15 – 34 | MEDIUM |
| 35 – 59 | HIGH |
| 60 – 100 | CRITICAL |

---

## Dependencies

See `requirements.txt`. The two main external libraries are:

- **requests** — HTTP communication
- **colorama** — colored terminal output

Everything else (`socket`, `threading`, `json`, `re`, `ipaddress`) is part of Python's standard library.

---

## Known Limitations

- Scans single domains or IPs only — IP range / CIDR notation not supported yet
- No wildcard DNS detection — domains with wildcard records may produce false positives in subdomain enumeration
- Large external wordlists (220k+ entries) can take several minutes for directory enumeration
- The WAF active detection phase sends attack-like payloads which may trigger IDS alerts on the target

---

## Future Improvements

- LLM API integration for natural language scan summaries
- CVE lookup from banner-grabbed version strings using the NVD API
- HTML and PDF report export
- IP range and CIDR scanning support
- Flask web interface for non-terminal users
- Wildcard DNS detection before subdomain enumeration

---

## References

- SecLists — https://github.com/danielmiessler/SecLists
- OWASP Top Ten — https://owasp.org/www-project-top-ten/
- Nmap Reference — https://nmap.org/book/man.html
- HackTricks — https://book.hacktricks.xyz
- Acunetix Test Site — http://testphp.vulnweb.com

---

*Arab Open University Egypt — Faculty of Computer Studies — TM471 Final Year Project — 2026*
