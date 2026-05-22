"""
ProjectZ v1.0 — Complete Module Guide
Displayed when user runs: python3 projectz.py modules
Army-grade reference with all 53 modules, every flag, every use case.
"""

from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

R  = Style.RESET_ALL
B  = Style.BRIGHT
DM = Style.DIM
C  = Fore.CYAN    + B
Y  = Fore.YELLOW  + B
G  = Fore.GREEN   + B
W  = Fore.WHITE   + B
RE = Fore.RED     + B
BL = Fore.BLUE    + B
M  = Fore.MAGENTA + B

# ── Full module metadata ───────────────────────────────────────────────────
MODULES: dict[str, dict] = {

# ════════════════════════════════════════════════════════════════════════════
"DOMAIN INTELLIGENCE": {
    "whois": {
        "cmd": "whois", "group": "domain", "key": False,
        "target": "domain",
        "desc": "Full WHOIS — registrar, owner, dates, nameservers, contact emails",
        "sources": ["WHOIS socket port 43", "IANA RDAP API", "ARIN / RIPE fallback"],
        "output": ["registrar", "creation_date", "expiration_date",
                   "nameservers[]", "registrant_org", "registrant_country", "emails[]"],
        "usage": [
            "python3 projectz.py example.com whois",
            "python3 projectz.py example.com whois -v",
            "python3 projectz.py example.com whois --no-cache",
        ],
        "tips": [
            "Contact emails useful for social-engineering research",
            "Expiry date reveals domain-takeover risk",
            "Nameservers identify CDN / hosting provider",
            "RDAP gives structured JSON — more reliable than raw WHOIS",
        ],
    },
    "dns": {
        "cmd": "dns", "group": "domain", "key": False,
        "target": "domain",
        "desc": "Full DNS record enumeration — A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, PTR",
        "sources": ["Cloudflare DoH 1.1.1.1", "Google DoH 8.8.8.8", "asyncio socket fallback"],
        "output": ["a[]", "aaaa[]", "mx[]", "txt[]", "ns[]", "cname", "soa", "caa[]", "ptr"],
        "usage": [
            "python3 projectz.py example.com dns",
            "python3 projectz.py example.com dns,spfdmarc",
        ],
        "tips": [
            "TXT records expose 3rd-party services (Stripe, Mailchimp, Twilio, etc.)",
            "MX reveals email provider — Google Workspace vs Microsoft 365 vs custom",
            "Multiple A records = load balancer / CDN (try each IP separately)",
            "Missing CAA = any CA can issue SSL certs for this domain",
            "PTR records on IPs can reveal internal hostnames",
        ],
    },
    "subdomains": {
        "cmd": "subdomains", "group": "domain", "key": False,
        "target": "domain",
        "desc": "Subdomain enumeration via DNS brute-force, CT logs, search engines, passive sources",
        "sources": ["DNS brute-force (wordlist)", "crt.sh CT logs",
                    "HackerTarget API", "RapidDNS", "AlienVault OTX",
                    "ThreatCrowd", "BufferOver.run"],
        "output": ["subdomains[]", "total", "sources_breakdown"],
        "usage": [
            "python3 projectz.py example.com subdomains",
            "python3 projectz.py example.com subdomains -v",
            "python3 projectz.py example.com crtsh,subdomains,dnsdump",
        ],
        "tips": [
            "dev.* / staging.* / test.* often have weaker WAFs and older software",
            "admin.* / portal.* / internal.* = admin panel candidates",
            "api.* reveals backend endpoints — often less protected",
            "vpn.* / remote.* / citrix.* = remote access entry points",
            "mail.* / smtp.* / mx.* = email infrastructure (SPF bypass potential)",
        ],
    },
    "ssl": {
        "cmd": "ssl", "group": "domain", "key": False,
        "target": "domain | IP",
        "desc": "SSL/TLS certificate analysis — SANs, issuer, expiry, cipher suites, weak ciphers",
        "sources": ["Direct TLS handshake", "crt.sh certificate DB"],
        "output": ["subject", "issuer", "san[]", "expiry", "days_left",
                   "protocols[]", "weak_ciphers[]", "self_signed"],
        "usage": [
            "python3 projectz.py example.com ssl",
            "python3 projectz.py 93.184.216.34 ssl",
        ],
        "tips": [
            "SANs (Subject Alt Names) reveal all domains on same certificate",
            "Self-signed certs on prod = misconfiguration",
            "TLS 1.0 / 1.1 still enabled = legacy vuln (POODLE, BEAST)",
            "Certificate expiry < 30 days = DoS risk if not renewed",
            "Wildcard certs (*.domain.com) — compromise one = all subdomains exposed",
        ],
    },
    "tech": {
        "cmd": "tech", "group": "domain", "key": False,
        "target": "domain",
        "desc": "Technology stack fingerprinting — web server, CMS, frameworks, cloud, CDN, analytics",
        "sources": ["HTTP response headers", "HTML meta tags",
                    "JS patterns", "Wappalyzer-style rules"],
        "output": ["server", "cms", "framework", "language", "cdn",
                   "analytics[]", "libraries[]", "cloud"],
        "usage": ["python3 projectz.py example.com tech"],
        "tips": [
            "Knowing the stack = knowing which CVEs apply",
            "PHP version in X-Powered-By → check for known RCEs",
            "jQuery version in JS → check for XSS (pre-3.5.0)",
            "Apache / Nginx version → known path traversal / misconfig CVEs",
        ],
    },
    "asn": {
        "cmd": "asn", "group": "domain", "key": False,
        "target": "domain | IP",
        "desc": "ASN lookup — autonomous system number, org, country, IP range, BGP peers",
        "sources": ["ipinfo.io", "bgp.he.net", "RIPE NCC"],
        "output": ["asn", "org", "country", "ip_range", "isp", "abuse_contact"],
        "usage": ["python3 projectz.py example.com asn", "python3 projectz.py 8.8.8.8 asn"],
        "tips": [
            "Same ASN as known malicious hosts = shared infrastructure",
            "IP range reveals other company-owned IPs (expand attack surface)",
            "Abuse contact = where to report or pivot on incident response",
        ],
    },
    "hosting": {
        "cmd": "hosting", "group": "domain", "key": False,
        "target": "domain",
        "desc": "Hosting provider, datacenter, cloud detection (AWS/GCP/Azure/DO/Cloudflare)",
        "sources": ["IP-API", "ipinfo.io", "ASN ranges"],
        "output": ["provider", "datacenter", "cloud", "ip", "city", "country"],
        "usage": ["python3 projectz.py example.com hosting"],
        "tips": [
            "Cloud provider → check for S3/GCS/Azure bucket misconfigs",
            "Same datacenter as other targets → shared tenant pivot",
        ],
    },
    "reverseip": {
        "cmd": "reverseip", "group": "domain", "key": False,
        "target": "domain | IP",
        "desc": "Reverse IP lookup — all domains hosted on same IP / shared hosting",
        "sources": ["HackerTarget Reverse IP", "ViewDNS.info", "SecurityTrails"],
        "output": ["domains[]", "total", "ip"],
        "usage": ["python3 projectz.py example.com reverseip",
                  "python3 projectz.py 93.184.216.34 reverseip"],
        "tips": [
            "Shared hosting: compromise any weak site = all sites on same server at risk",
            "Virtual hosting misconfig can expose other sites via Host header injection",
            "Many domains on one IP = likely shared/budget hosting (less hardened)",
        ],
    },
    "spfdmarc": {
        "cmd": "spfdmarc", "group": "domain", "key": False,
        "target": "domain",
        "desc": "SPF / DMARC / DKIM policy analysis — email spoofing vulnerability assessment",
        "sources": ["DNS TXT record query"],
        "output": ["spf_record", "spf_valid", "spf_too_many_lookups",
                   "dmarc_record", "dmarc_policy", "dmarc_pct",
                   "dkim_selector", "spoofable"],
        "usage": ["python3 projectz.py example.com spfdmarc"],
        "tips": [
            "No SPF = domain spoofable in phishing emails",
            "SPF ~all (softfail) = still spoofable in many mail clients",
            "No DMARC = no enforcement even if SPF/DKIM pass",
            "DMARC p=none = monitoring only, no protection — spoofing still possible",
            "DMARC pct < 100 = only partial enforcement",
        ],
    },
    "headers": {
        "cmd": "headers", "group": "domain", "key": False,
        "target": "domain",
        "desc": "HTTP security headers audit — OWASP grade A+–F, cookie flags, info disclosure",
        "sources": ["Direct HTTP/HTTPS probe"],
        "output": ["grade", "score", "headers_present[]", "headers_missing[]",
                   "info_disclosure[]", "cookie_issues[]", "csp_analysis",
                   "hsts_analysis"],
        "usage": ["python3 projectz.py example.com headers",
                  "python3 projectz.py example.com headers -v"],
        "tips": [
            "Missing CSP = XSS attacks can execute arbitrary JS",
            "Missing HSTS = HTTPS downgrade / MITM possible",
            "Server: header reveals version — remove or obfuscate in production",
            "X-Powered-By: PHP/8.1 → check PHP 8.1 CVEs immediately",
            "Cookies without Secure/HttpOnly/SameSite = session hijack / CSRF risk",
        ],
    },
    "cors": {
        "cmd": "cors", "group": "domain", "key": False,
        "target": "domain",
        "desc": "CORS misconfiguration scanner — 10 bypass techniques + PoC JS exploit generation",
        "sources": ["Direct HTTP probe with crafted Origin headers"],
        "output": ["vulnerable", "vulnerabilities[]", "poc[]", "critical_findings[]"],
        "usage": ["python3 projectz.py example.com cors",
                  "python3 projectz.py example.com cors -v"],
        "tips": [
            "ACAO: * + ACAC: true = CRITICAL (any site can read your authenticated API)",
            "Origin reflection = attacker hosts evil.com to read target's API responses",
            "Null origin trust = exploitable from sandboxed iframes (PDF embeds, etc.)",
            "HTTP origin on HTTPS endpoint = downgrade CORS bypass",
            "PoC JS code is generated automatically — test in browser console",
        ],
    },
    "cms": {
        "cmd": "cms", "group": "domain", "key": False,
        "target": "domain",
        "desc": "CMS & framework detection — WordPress, Drupal, Joomla, Django, Laravel, Rails + 8 more",
        "sources": ["HTTP headers", "HTML fingerprinting",
                    "Path probing", "Version files"],
        "output": ["cms", "version", "category", "confidence",
                   "technologies[]", "vuln_paths_found[]"],
        "usage": ["python3 projectz.py example.com cms"],
        "tips": [
            "WordPress xmlrpc.php accessible = brute-force / amplification attack vector",
            "/.env accessible on Laravel = full credential dump",
            "Spring Boot /actuator/heapdump = memory dump with secrets",
            "Joomla CHANGELOG.txt = reveals exact version for exploit matching",
            "Outdated WordPress plugins = most common web compromise vector",
        ],
    },
},

# ════════════════════════════════════════════════════════════════════════════
"PEOPLE & OSINT": {
    "emails": {
        "cmd": "emails", "group": "people", "key": False,
        "target": "domain",
        "desc": "Email harvesting — Hunter.io scrape, Google/Bing dorks, cert SANs, LinkedIn patterns",
        "sources": ["Hunter.io public API", "Google dork: site:domain email",
                    "Bing dork", "crt.sh SANs", "GitHub commits"],
        "output": ["emails[]", "total", "sources_breakdown", "patterns_found[]"],
        "usage": ["python3 projectz.py example.com emails",
                  "python3 projectz.py example.com emails,breach,hibp"],
        "tips": [
            "Format detection reveals naming convention (first.last@, flast@)",
            "Predict employee emails once format is known",
            "Cross-reference with breach data for credential stuffing risk",
        ],
    },
    "phones": {
        "cmd": "phones", "group": "people", "key": False,
        "target": "domain",
        "desc": "Phone number discovery via Google/Bing dorks and website scraping",
        "sources": ["Google dork", "Bing dork", "Direct site scrape"],
        "output": ["phones[]", "total"],
        "usage": ["python3 projectz.py example.com phones"],
        "tips": [
            "Phone numbers useful for vishing (voice phishing) campaigns",
            "Mobile numbers can be used for SIM-swap research",
        ],
    },
    "linkedin": {
        "cmd": "linkedin", "group": "people", "key": False,
        "target": "domain",
        "desc": "LinkedIn employee enumeration via Google/Bing dork — names, titles, departments",
        "sources": ["Google dork: site:linkedin.com company",
                    "Bing dork"],
        "output": ["employees[]", "departments[]", "total"],
        "usage": ["python3 projectz.py example.com linkedin"],
        "tips": [
            "IT/Security staff titles reveal technology stack",
            "C-level names valuable for spear-phishing lures",
            "Combine with emails module: predict first.last@company.com",
        ],
    },
    "twitter": {
        "cmd": "twitter", "group": "people", "key": False,
        "target": "domain | username",
        "desc": "Twitter/X profile and employee discovery via search",
        "sources": ["Twitter search (unauthenticated)"],
        "output": ["profiles[]", "total"],
        "usage": ["python3 projectz.py example.com twitter",
                  "python3 projectz.py @username twitter"],
        "tips": [
            "Employees posting internal tools / tech stack by accident",
            "Job postings reveal internal software being used",
        ],
    },
    "github": {
        "cmd": "github", "group": "people", "key": True,
        "target": "domain | username",
        "desc": "GitHub intelligence — repos, commit emails, leaked secrets, API keys in code",
        "sources": ["GitHub Search API", "GitHub Code Search",
                    "Commit history analysis"],
        "output": ["repos[]", "commit_emails[]", "secrets_found[]",
                   "org_members[]", "total"],
        "usage": ["python3 projectz.py example.com github",
                  "python3 projectz.py examplecorp github -v"],
        "tips": [
            "API keys, passwords, private keys committed to public repos",
            "Commit history emails reveal internal developer addresses",
            "Look for .env files, config.yml, secrets.json in repos",
            "GITHUB_TOKEN in .env → 5000 req/hr vs 60 unauthenticated",
        ],
    },
    "usernames": {
        "cmd": "usernames", "group": "people", "key": False,
        "target": "username | domain",
        "desc": "Username presence check across 80+ platforms",
        "sources": ["80+ platform HTTP probes"],
        "output": ["found[]", "not_found[]", "total_found"],
        "usage": ["python3 projectz.py johndoe usernames",
                  "python3 projectz.py @johndoe usernames"],
        "tips": [
            "Same username across platforms = profile correlation",
            "Profile photos from one platform can ID person on others (reverse image)",
        ],
    },
    "breach": {
        "cmd": "breach", "group": "people", "key": True,
        "target": "domain | email",
        "desc": "Data breach lookup — HIBP, DeHashed scrape, breach aggregators",
        "sources": ["HaveIBeenPwned v3 API (domain free, email needs key)",
                    "DeHashed public endpoint", "IntelligenceX"],
        "output": ["breaches[]", "paste_hits[]", "total_breached_accounts"],
        "usage": ["python3 projectz.py example.com breach",
                  "python3 projectz.py admin@example.com breach"],
        "tips": [
            "Breached domain = credential stuffing risk against your auth",
            "Old breach passwords may still be in use (password reuse ~50%)",
            "Pastebin hits = credentials likely already circulating",
        ],
    },
    "employees": {
        "cmd": "employees", "group": "people", "key": True,
        "target": "domain",
        "desc": "Employee enumeration — LinkedIn dork + GitHub org + Hunter.io scrape",
        "sources": ["LinkedIn Google dork", "GitHub org member API",
                    "Hunter.io domain search"],
        "output": ["employees[]", "departments[]", "emails[]", "total"],
        "usage": ["python3 projectz.py example.com employees"],
        "tips": [
            "Combine with spfdmarc — if domain is spoofable, use employee names for phishing",
            "IT department employees → target for spear-phishing pretexts",
        ],
    },
},

# ════════════════════════════════════════════════════════════════════════════
"NETWORK & INFRASTRUCTURE": {
    "portscan": {
        "cmd": "portscan", "group": "network", "key": False,
        "target": "domain | IP",
        "desc": "Port scanner — nmap (if installed) or async TCP connect fallback (top 1000 ports)",
        "sources": ["nmap (external tool)", "asyncio TCP connect (built-in)"],
        "output": ["open_ports[]", "services", "os_guess", "total"],
        "usage": ["python3 projectz.py example.com portscan",
                  "python3 projectz.py 192.168.1.1 portscan",
                  "python3 projectz.py 10.0.0.1 portscan --timeout 30"],
        "tips": [
            "3389 open = RDP exposed to internet (brute-force / BlueKeep)",
            "445 open = SMB exposed (EternalBlue / PrintNightmare)",
            "6379 open = Redis likely unauthenticated (full RCE)",
            "27017 open = MongoDB likely unauthenticated (data dump)",
            "8888 open = Jupyter Notebook (code execution)",
            "2375 open = Docker daemon unauthenticated (container escape)",
        ],
    },
    "masscan": {
        "cmd": "masscan", "group": "network", "key": False,
        "target": "IP | CIDR range",
        "desc": "High-speed mass TCP port scanner using masscan binary",
        "sources": ["masscan (external tool — must be installed)"],
        "output": ["open_ports[]", "total", "scan_rate"],
        "usage": ["python3 projectz.py 192.168.1.0/24 masscan",
                  "python3 projectz.py 10.0.0.1 masscan"],
        "tips": [
            "Requires masscan installed: apt install masscan",
            "May require sudo for raw socket access",
            "Use on internal networks during authorized assessments",
            "Rate limit with --rate flag to avoid IDS triggering",
        ],
    },
    "geo": {
        "cmd": "geo", "group": "network", "key": False,
        "target": "IP | domain",
        "desc": "IP geolocation — city, country, ISP, lat/lon, timezone",
        "sources": ["ip-api.com", "ipinfo.io", "ipwhois.io"],
        "output": ["ip", "city", "region", "country", "isp", "lat", "lon", "timezone"],
        "usage": ["python3 projectz.py 8.8.8.8 geo",
                  "python3 projectz.py example.com geo"],
        "tips": [
            "Country of origin important for compliance / incident attribution",
            "ISP info helps confirm cloud provider (AWS, GCP, Azure, etc.)",
        ],
    },
    "iprep": {
        "cmd": "iprep", "group": "network", "key": False,
        "target": "IP",
        "desc": "IP reputation — GreyNoise, AbuseIPDB, Emerging Threats, SpamHaus",
        "sources": ["GreyNoise Community API", "AbuseIPDB API",
                    "Emerging Threats blocklist", "SpamHaus zen"],
        "output": ["reputation", "abuse_score", "threat_feeds[]",
                   "tor_exit", "vpn", "hosting", "tags[]"],
        "usage": ["python3 projectz.py 1.2.3.4 iprep"],
        "tips": [
            "GreyNoise 'riot' = known benign (Google, AWS, etc.) — ignore in alerts",
            "High AbuseIPDB confidence + low reports = likely new attacker IP",
            "Tor exit node = anonymized traffic — treat with elevated suspicion",
        ],
    },
    "shodan": {
        "cmd": "shodan", "group": "network", "key": True,
        "target": "IP | domain",
        "desc": "Shodan device intelligence — open ports, banners, CVEs, historical data",
        "sources": ["Shodan internetdb.shodan.io (free, no key)",
                    "Shodan API (key needed for full results)"],
        "output": ["open_ports[]", "services[]", "vulns[]", "hostnames[]",
                   "tags[]", "last_seen"],
        "usage": ["python3 projectz.py 8.8.8.8 shodan",
                  "python3 projectz.py example.com shodan"],
        "tips": [
            "Shodan tags: 'self-signed', 'honeypot', 'cloud' — important filters",
            "CVEs listed by Shodan are confirmed via banner matching",
            "Historical data (with key) shows ports that were open previously",
        ],
    },
    "censys": {
        "cmd": "censys", "group": "network", "key": True,
        "target": "IP | domain",
        "desc": "Censys internet scan data — certificates, open services, protocol details",
        "sources": ["Censys Search API (250 queries/month free)"],
        "output": ["ip", "services[]", "cert_subjects[]", "protocols[]"],
        "usage": ["python3 projectz.py example.com censys"],
        "tips": [
            "Certificate subject history reveals IPs that had a domain's SSL cert",
            "Useful for finding origin IP behind Cloudflare",
        ],
    },
    "zoomeye": {
        "cmd": "zoomeye", "group": "network", "key": True,
        "target": "IP | domain",
        "desc": "ZoomEye (Chinese Shodan) — IoT and service intelligence from Chinese perspective",
        "sources": ["ZoomEye API (10k results/month free)"],
        "output": ["services[]", "open_ports[]", "banners[]", "country"],
        "usage": ["python3 projectz.py example.com zoomeye"],
        "tips": [
            "Picks up devices Shodan misses — especially in APAC region",
            "Good for IoT device discovery",
        ],
    },
    "banner": {
        "cmd": "banner", "group": "network", "key": False,
        "target": "IP | domain",
        "desc": "Service banner grabbing — raw TCP banners, version strings, SSH fingerprints",
        "sources": ["Onyphe API (free tier)", "Direct async TCP connect"],
        "output": ["banners[]", "ssh_fingerprint", "ftp_banner", "smtp_banner"],
        "usage": ["python3 projectz.py 8.8.8.8 banner"],
        "tips": [
            "SSH banner version → check for known SSH CVEs",
            "FTP banner often reveals OS + FTP server version",
            "SMTP banner → server software for phishing infrastructure analysis",
        ],
    },
    "waf": {
        "cmd": "waf", "group": "network", "key": False,
        "target": "domain",
        "desc": "WAF/CDN fingerprinting — Cloudflare, Imperva, Akamai, AWS WAF, F5, ModSecurity + 10 more",
        "sources": ["HTTP response headers analysis", "Cookie fingerprinting",
                    "Body signature matching", "DNS CNAME chain",
                    "Active probe with crafted payloads"],
        "output": ["waf", "cdn", "confidence", "bypass_hints[]",
                   "detections[]", "probe_results[]"],
        "usage": ["python3 projectz.py example.com waf",
                  "python3 projectz.py example.com waf -v"],
        "tips": [
            "bypass_hints gives specific techniques per WAF vendor",
            "Low confidence = WAF may be misconfigured (easier to bypass)",
            "CDN detection helps find origin IP via historical DNS",
            "Cloudflare: find origin via Shodan ssl.cert.subject.CN search",
            "None detected = no WAF — direct testing without restrictions",
        ],
    },
},

# ════════════════════════════════════════════════════════════════════════════
"SEARCH ENGINE DORKING": {
    "files": {
        "cmd": "files", "group": "dorking", "key": False,
        "target": "domain",
        "desc": "Sensitive file discovery via Google/Bing dorks — configs, backups, logs, docs",
        "sources": ["Google dork: site:domain filetype:*",
                    "Bing dork"],
        "output": ["files_found[]", "categories[]", "total"],
        "usage": ["python3 projectz.py example.com files"],
        "tips": [
            "filetype:sql = database backups (often contain credentials)",
            "filetype:log = application logs (stack traces, usernames)",
            "filetype:bak / .backup = configuration backups",
            ".env files indexed = credentials exposed publicly",
            "Excel/CSV files may contain PII or internal data",
        ],
    },
    "admin": {
        "cmd": "admin", "group": "dorking", "key": False,
        "target": "domain",
        "desc": "Admin panel discovery — wordlist probe (200+ paths) + login page detection",
        "sources": ["Direct HTTP probe", "Wordlist brute-force"],
        "output": ["panels_found[]", "paths_tested", "login_pages[]"],
        "usage": ["python3 projectz.py example.com admin"],
        "tips": [
            "/wp-admin, /administrator, /cpanel, /plesk, /phpmyadmin",
            "/jenkins, /grafana, /kibana, /portainer — DevOps panels",
            "/.env, /.git/config — critical if accessible",
            "/actuator, /actuator/env — Spring Boot (full config dump)",
            "403 = path exists but denied — worth further probing",
        ],
    },
    "errors": {
        "cmd": "errors", "group": "dorking", "key": False,
        "target": "domain",
        "desc": "Error message discovery — stack traces, SQL errors, debug pages, version strings",
        "sources": ["Google dork: site:domain error",
                    "Direct probe of common error-triggering paths"],
        "output": ["error_pages[]", "stack_traces[]", "db_errors[]"],
        "usage": ["python3 projectz.py example.com errors"],
        "tips": [
            "Stack traces = full file paths, class names, framework details",
            "SQL errors = database type and query structure (SQLi potential)",
            "Debug=True in Django/Flask = full interactive debugger exposed",
        ],
    },
    "creds": {
        "cmd": "creds", "group": "dorking", "key": True,
        "target": "domain",
        "desc": "Credential exposure via GitHub dorks, Pastebin, Google dorks for passwords/tokens",
        "sources": ["GitHub Code Search API", "Google dork",
                    "Pastebin search"],
        "output": ["credentials_found[]", "api_keys[]", "passwords[]"],
        "usage": ["python3 projectz.py example.com creds"],
        "tips": [
            "Searches GitHub for: password, api_key, secret, token for domain",
            "Found credentials should be tested for validity (authorized use only)",
            "API keys in public repos still valid ~30% of the time",
        ],
    },
    "vulns": {
        "cmd": "vulns", "group": "dorking", "key": False,
        "target": "domain",
        "desc": "Vulnerability dorks — known CVE-matching paths, misconfigured endpoints",
        "sources": ["Google dork", "Bing dork", "Common vuln path probing"],
        "output": ["vuln_hints[]", "paths_found[]", "total"],
        "usage": ["python3 projectz.py example.com vulns"],
        "tips": [
            "Dorks for: intitle:index.of, inurl:php?id=, inurl:upload",
            "Matches known vulnerable path patterns to existing CVEs",
        ],
    },
    "dirbust": {
        "cmd": "dirbust", "group": "dorking", "key": False,
        "target": "domain",
        "desc": "Directory/path brute-forcing with built-in wordlist",
        "sources": ["Async HTTP probe against wordlist"],
        "output": ["paths_found[]", "status_codes", "total_tested"],
        "usage": ["python3 projectz.py example.com dirbust"],
        "tips": [
            "Looks for 200, 301, 302, 403 responses",
            "403 = path exists but protected — note for further testing",
            "Combine with admin module for comprehensive path coverage",
        ],
    },
},

# ════════════════════════════════════════════════════════════════════════════
"DATA HARVESTING": {
    "google": {
        "cmd": "google", "group": "harvesting", "key": False,
        "target": "domain",
        "desc": "Google search harvesting — indexed pages, sensitive dorks, email exposure",
        "sources": ["Google Search (scraped, no API key needed)"],
        "output": ["results[]", "emails_found[]", "sensitive_pages[]", "total"],
        "usage": ["python3 projectz.py example.com google"],
        "tips": [
            "Harvests: site:domain, intitle:, inurl:, filetype: results",
            "Rotates User-Agent to avoid blocks",
            "Polite delay between requests (1.5–3s) — avoids CAPTCHA",
        ],
    },
    "bing": {
        "cmd": "bing", "group": "harvesting", "key": False,
        "target": "domain",
        "desc": "Bing search harvesting — different index than Google, catches different results",
        "sources": ["Bing Search (scraped)"],
        "output": ["results[]", "api_endpoints[]", "emails_found[]", "total"],
        "usage": ["python3 projectz.py example.com bing"],
        "tips": [
            "Bing often indexes API endpoints Google misses",
            "Use alongside google for full coverage",
            "Bing dork for API: site:domain inurl:/api/ OR inurl:/v1/",
        ],
    },
    "crtsh": {
        "cmd": "crtsh", "group": "harvesting", "key": False,
        "target": "domain",
        "desc": "Certificate Transparency log harvesting — all SSL certs ever issued for domain",
        "sources": ["crt.sh (Comodo CT log aggregator)"],
        "output": ["certificates[]", "domains_found[]", "total"],
        "usage": ["python3 projectz.py example.com crtsh"],
        "tips": [
            "Reveals ALL subdomains that ever had a certificate issued",
            "Including dev/staging/internal that may still be alive",
            "Historical certs show infrastructure changes over time",
        ],
    },
    "dnsdump": {
        "cmd": "dnsdump", "group": "harvesting", "key": False,
        "target": "domain",
        "desc": "DNSDumpster passive DNS harvesting — subdomains, IPs, mail servers, hosts",
        "sources": ["dnsdumpster.com"],
        "output": ["subdomains[]", "ips[]", "mx_records[]", "total"],
        "usage": ["python3 projectz.py example.com dnsdump"],
        "tips": [
            "Often finds subdomains crtsh misses (different data source)",
            "Use alongside crtsh and subdomains for maximum coverage",
        ],
    },
    "leaks": {
        "cmd": "leaks", "group": "harvesting", "key": True,
        "target": "domain",
        "desc": "Data leak intelligence — HIBP, Pastebin dumps, LeakCheck aggregation",
        "sources": ["HaveIBeenPwned API", "Pastebin dump search",
                    "GitHub gist search"],
        "output": ["leaks[]", "paste_hits[]", "breach_count", "total"],
        "usage": ["python3 projectz.py example.com leaks"],
        "tips": [
            "Corroborates breach module data with additional sources",
            "Pastebin hits often contain raw credential dumps",
        ],
    },
    "histdns": {
        "cmd": "histdns", "group": "harvesting", "key": True,
        "target": "domain",
        "desc": "Historical DNS records — past IPs, nameservers, origin IP before CDN",
        "sources": ["SecurityTrails API (free tier)", "PassiveDNS sources"],
        "output": ["history[]", "old_ips[]", "nameserver_changes[]"],
        "usage": ["python3 projectz.py example.com histdns"],
        "tips": [
            "Key technique: find origin IP behind Cloudflare from historical DNS",
            "Old IPs may still be live and bypassing WAF rules",
            "NS changes reveal hosting provider migrations",
        ],
    },
    "hunter": {
        "cmd": "hunter", "group": "harvesting", "key": True,
        "target": "domain",
        "desc": "Hunter.io alternative — email pattern discovery, domain email harvesting",
        "sources": ["Hunter.io public search", "GitHub commit email scraping",
                    "Google dork for emails"],
        "output": ["emails[]", "pattern", "pattern_confidence", "total"],
        "usage": ["python3 projectz.py example.com hunter"],
        "tips": [
            "Pattern detection: first.last@, f.last@, firstl@ etc.",
            "Once pattern known: predict ANY employee email",
            "Cross-check with LinkedIn employee list for full enumeration",
        ],
    },
    "s3buckets": {
        "cmd": "s3buckets", "group": "harvesting", "key": False,
        "target": "domain",
        "desc": "Cloud bucket finder — AWS S3, GCS, Azure Blob, DigitalOcean Spaces",
        "sources": ["Direct HTTP probe", "DNS resolution",
                    "60+ permutation-based name generation"],
        "output": ["buckets_found[]", "open_buckets[]",
                   "writable_buckets[]", "critical_findings[]"],
        "usage": ["python3 projectz.py example.com s3buckets"],
        "tips": [
            "public-write bucket = CRITICAL — attacker can upload files",
            "public-read = check for PII, credentials, backups in listed files",
            "Permutations: company-backup, company-assets, company-staging etc.",
            "Azure Blob listing at /?comp=list if Container ACL = public",
        ],
    },
},

# ════════════════════════════════════════════════════════════════════════════
"CYBERSEC & THREAT INTEL": {
    "virustotal": {
        "cmd": "virustotal", "group": "cybersec", "key": True,
        "target": "domain | IP | URL | hash",
        "desc": "Multi-engine reputation — VirusTotal v3, URLVoid, PhishTank, OpenPhish, Sucuri, SafeBrowsing",
        "sources": ["VirusTotal API v3 (FREE 4/min with key)",
                    "URLVoid 30+ AV aggregator (free scrape)",
                    "PhishTank verified phishing DB",
                    "OpenPhish live feed",
                    "Sucuri SiteCheck",
                    "Google Safe Browsing (key needed)"],
        "output": ["detection_ratio", "vendors_flagged[]", "malware_families[]",
                   "categories[]", "reputation_score", "last_analysis"],
        "usage": ["python3 projectz.py example.com virustotal",
                  "python3 projectz.py 1.2.3.4 virustotal",
                  "python3 projectz.py d41d8cd98f00b204e9800998ecf8427e virustotal"],
        "tips": [
            "Without key: falls back to URLVoid + PhishTank (still useful)",
            "Detection ratio > 5/70 vendors = likely malicious",
            "Malware families identified: Emotet, Cobalt Strike, AsyncRAT etc.",
        ],
    },
    "urlscan": {
        "cmd": "urlscan", "group": "cybersec", "key": True,
        "target": "domain | URL",
        "desc": "URLScan.io scan results — screenshot, DOM analysis, network requests, DOM XSS",
        "sources": ["URLScan.io API (5000/month free with key)"],
        "output": ["scan_url", "screenshot_url", "js_files[]", "requests[]",
                   "verdicts", "dom_xss"],
        "usage": ["python3 projectz.py example.com urlscan"],
        "tips": [
            "Screenshots useful for report documentation",
            "Network requests reveal 3rd-party services loaded",
            "DOM analysis can reveal JS-based XSS sinks",
        ],
    },
    "hibp": {
        "cmd": "hibp", "group": "cybersec", "key": True,
        "target": "domain | email",
        "desc": "HaveIBeenPwned — breach and paste checks for domain and individual emails",
        "sources": ["HIBP v3 API (domain free, email search needs key)"],
        "output": ["breaches[]", "paste_hits[]", "total_pwned"],
        "usage": ["python3 projectz.py example.com hibp",
                  "python3 projectz.py admin@example.com hibp"],
        "tips": [
            "Domain search is FREE — no key needed",
            "Per-email check needs HIBP_API_KEY (£3.50/month)",
            "Most impactful breaches: LinkedIn, Adobe, Dropbox (widespread reuse)",
        ],
    },
    "otx": {
        "cmd": "otx", "group": "cybersec", "key": True,
        "target": "domain | IP | hash",
        "desc": "AlienVault OTX — threat pulses, IOCs, malware campaigns, TTP analysis",
        "sources": ["OTX API (unlimited free with key)"],
        "output": ["pulses[]", "iocs[]", "malware_families[]",
                   "threat_score", "country_origin"],
        "usage": ["python3 projectz.py example.com otx",
                  "python3 projectz.py 1.2.3.4 otx"],
        "tips": [
            "OTX pulses link to full threat intelligence reports",
            "Multiple pulses = well-known threat actor infrastructure",
            "OTX is free and unlimited — always worth running",
        ],
    },
    "abuseipdb": {
        "cmd": "abuseipdb", "group": "cybersec", "key": True,
        "target": "IP",
        "desc": "AbuseIPDB + GreyNoise — IP abuse reports, attack categories, scan/spray patterns",
        "sources": ["AbuseIPDB API (1000/day free)",
                    "GreyNoise Community API (free)"],
        "output": ["abuse_confidence_score", "total_reports", "categories[]",
                   "last_reported", "greynoise_classification", "tags[]"],
        "usage": ["python3 projectz.py 1.2.3.4 abuseipdb"],
        "tips": [
            "Score > 80% = high confidence malicious",
            "Categories: SSH brute force, web scan, spam, DDoS etc.",
            "GreyNoise 'malicious' = active threat actor scanning",
            "GreyNoise 'benign' = known scanner (Shodan, Censys, etc.)",
        ],
    },
    "urlhaus": {
        "cmd": "urlhaus", "group": "cybersec", "key": False,
        "target": "domain | IP | URL",
        "desc": "URLhaus malware URL database — active malware distribution URLs",
        "sources": ["abuse.ch URLhaus API (free, no key)"],
        "output": ["urls[]", "malware_families[]", "status", "tags[]"],
        "usage": ["python3 projectz.py example.com urlhaus"],
        "tips": [
            "No API key needed — fully free",
            "Finds active malware distribution infrastructure",
            "Tags: emotet, cobalt-strike, formbook, payload-hosting etc.",
        ],
    },
    "exploitdb": {
        "cmd": "exploitdb", "group": "cybersec", "key": False,
        "target": "domain | software",
        "desc": "ExploitDB + NVD CVE search — public exploits for detected technologies",
        "sources": ["ExploitDB search API", "NVD NIST CVE API (free)",
                    "CVSS v3 scoring"],
        "output": ["exploits[]", "cves[]", "cvss_scores", "severity_breakdown"],
        "usage": ["python3 projectz.py example.com exploitdb"],
        "tips": [
            "Correlates with tech module findings for CVE matching",
            "CVSS 9.0+ = critical — prioritize immediately",
            "Filter by 'verified' exploits for highest confidence",
        ],
    },
    "pastebin": {
        "cmd": "pastebin", "group": "cybersec", "key": False,
        "target": "domain | email",
        "desc": "Pastebin and paste site dumps — credential leaks, config dumps, code leaks",
        "sources": ["psbdmp.ws API", "PasteSearch", "Google dork"],
        "output": ["pastes[]", "credentials_in_pastes", "total"],
        "usage": ["python3 projectz.py example.com pastebin"],
        "tips": [
            "Pastes containing credentials are often fresh leaks",
            "Config files in pastes may expose internal architecture",
        ],
    },
    "intelx": {
        "cmd": "intelx", "group": "cybersec", "key": True,
        "target": "domain | email | IP",
        "desc": "Intelligence X — dark web, breach, paste, and document intelligence",
        "sources": ["IntelligenceX API (limited free tier)"],
        "output": ["results[]", "dark_web_hits", "document_hits", "total"],
        "usage": ["python3 projectz.py example.com intelx"],
        "tips": [
            "IntelX indexes dark web forums, breach databases, documents",
            "Often finds data no other source has",
        ],
    },
    "yara": {
        "cmd": "yara", "group": "cybersec", "key": True,
        "target": "domain | hash",
        "desc": "Hybrid Analysis + YARA — malware behavioral analysis and signature matching",
        "sources": ["Hybrid Analysis API (free with key)",
                    "YARA pattern matching on fetched content"],
        "output": ["verdict", "threat_score", "signatures[]",
                   "network_iocs[]", "file_iocs[]"],
        "usage": ["python3 projectz.py d41d8cd98f00b204e9800998ecf8427e yara"],
        "tips": [
            "Submit hashes of files found on target infrastructure",
            "Behavioral analysis reveals C2 connections, persistence mechanisms",
        ],
    },
    "threatcrowd": {
        "cmd": "threatcrowd", "group": "cybersec", "key": False,
        "target": "domain | IP | email",
        "desc": "ThreatCrowd alternative — graph-based threat intelligence, related IOCs",
        "sources": ["ThreatCrowd API / AlienVault OTX graph"],
        "output": ["related_domains[]", "related_ips[]", "hashes[]",
                   "emails[]", "references[]"],
        "usage": ["python3 projectz.py example.com threatcrowd"],
        "tips": [
            "Graph model reveals full threat actor infrastructure",
            "Related IPs from one malicious domain = expand pivot",
        ],
    },
    "packetstorm": {
        "cmd": "packetstorm", "group": "cybersec", "key": False,
        "target": "domain | CVE | software",
        "desc": "PacketStorm Security — exploit archives, PoC tools, advisory search",
        "sources": ["PacketStorm public search"],
        "output": ["exploits[]", "advisories[]", "tools[]", "total"],
        "usage": ["python3 projectz.py example.com packetstorm"],
        "tips": [
            "Contains exploits not in ExploitDB",
            "Often has PoC tools ready to test (authorized use only)",
        ],
    },
},

}  # end MODULES


# ════════════════════════════════════════════════════════════════════════════
#  PRINT FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def _divider(char="═", width=74):
    print(f"  {DM}{char * width}{R}")

def _hdivider(char="─", width=74):
    print(f"  {DM}{char * width}{R}")

def _header():
    print()
    _divider("═")
    print(f"  {C}  ProjectZ v1.0{R}  {DM}·{R}  {W}Complete Module Reference{R}  "
          f"  {DM}by cyberhowler (R.G){R}")
    _divider("═")
    print()

def _footer():
    print()
    _divider("═")
    print(f"  {C}QUICK USAGE{R}")
    _hdivider()
    cmds = [
        ("Run single module",        "python3 projectz.py <target> <module>"),
        ("Run module group",         "python3 projectz.py <target> domain.all"),
        ("Run named profile",        "python3 projectz.py <target> --profile red_team"),
        ("Multiple modules",         "python3 projectz.py <target> waf,headers,cors,cms"),
        ("Full scan + HTML report",  "python3 projectz.py <target> full -f html"),
        ("Verbose output",           "python3 projectz.py <target> <module> -v"),
        ("Skip cache",               "python3 projectz.py <target> <module> --no-cache"),
        ("Watch mode",               "python3 projectz.py <target> quick --watch 6"),
        ("Compare last 2 scans",     "python3 projectz.py --compare <target>"),
        ("Check API key status",     "python3 projectz.py --preflight"),
        ("List all profiles",        "python3 projectz.py --list-profiles"),
        ("DB summary for target",    "python3 projectz.py --db-summary <target>"),
    ]
    for label, cmd in cmds:
        print(f"  {DM}{label:<28}{R}  {C}{cmd}{R}")
    print()
    _divider("═")
    print(f"  {DM}Profiles:{R} quick · full · pentest · red_team · bug_bounty · "
          f"passive_recon · web_audit · social_eng · osint · threat_intel · domain")
    _divider("═")
    print()


def _print_module_block(name: str, info: dict):
    """Print one module's full info block."""
    key_tag  = f" {Y}[API key optional]{R}" if info.get("key") else ""
    grp_tag  = f"{DM}group:{info.get('group','')}{R}"
    tgt_tag  = f"{DM}target: {info.get('target','any')}{R}"

    _hdivider()
    print(f"  {G} {name.upper()}{R}  {grp_tag}  {tgt_tag}{key_tag}")
    print(f"  {DM}  {info['desc']}{R}")
    print()

    # Sources
    sources = info.get("sources", [])
    if sources:
        print(f"  {BL}  Sources{R}  {DM}:{R}")
        for s in sources:
            print(f"        {DM}·{R} {s}")

    # Output fields
    output = info.get("output", [])
    if output:
        print(f"  {BL}  Output fields{R}  {DM}:{R}  {DM}{', '.join(output)}{R}")

    # Usage
    usage = info.get("usage", [])
    if usage:
        print(f"  {BL}  Usage{R}  {DM}:{R}")
        for u in usage:
            print(f"        {C}{u}{R}")

    # Tips
    tips = info.get("tips", [])
    if tips:
        print(f"  {BL}  Pentest tips{R}  {DM}:{R}")
        for t in tips:
            print(f"        {DM}→{R} {t}")
    print()


def print_full_guide():
    """Print the full module guide — all sections, all modules."""
    _header()

    total_mods = sum(len(v) for v in MODULES.values())
    print(f"  {W}{total_mods} modules{R} across {W}{len(MODULES)} groups{R}  "
          f"  {DM}(use  python3 projectz.py modules <group>  to filter){R}")
    print()

    section_icons = {
        "DOMAIN INTELLIGENCE":        "◈  DOMAIN INTELLIGENCE",
        "PEOPLE & OSINT":             "◈  PEOPLE & OSINT",
        "NETWORK & INFRASTRUCTURE":   "◈  NETWORK & INFRASTRUCTURE",
        "SEARCH ENGINE DORKING":      "◈  SEARCH ENGINE DORKING",
        "DATA HARVESTING":            "◈  DATA HARVESTING",
        "CYBERSEC & THREAT INTEL":    "◈  CYBERSEC & THREAT INTEL",
    }

    for section_name, section_mods in MODULES.items():
        icon = section_icons.get(section_name, section_name)
        print()
        _divider("━")
        print(f"  {M}  {icon}{R}  {DM}({len(section_mods)} modules){R}")
        _divider("━")
        for mod_name, mod_info in section_mods.items():
            _print_module_block(mod_name, mod_info)

    _footer()


def print_compact_list():
    """Print compact one-liner per module — for --list-modules."""
    _header()
    print(f"  {C}COMPACT MODULE LIST{R}  {DM}(use  python3 projectz.py modules <name>  for details){R}")
    print()
    for section_name, section_mods in MODULES.items():
        print(f"  {M}{section_name}{R}")
        for mod_name, mod_info in section_mods.items():
            key = f" {Y}*{R}" if mod_info.get("key") else "  "
            tgt = f"{DM}{mod_info.get('target','any'):<22}{R}"
            print(f"   {key} {G}{mod_name:<14}{R}  {tgt}  {DM}{mod_info['desc'][:55]}{R}")
        print()

    print(f"  {DM}* = benefits from optional API key (see .env.example){R}")
    print()


def _print_module(mod_name: str):
    """Print details for one specific module."""
    for section_mods in MODULES.values():
        if mod_name.lower() in section_mods:
            _header()
            _print_module_block(mod_name.lower(), section_mods[mod_name.lower()])
            _footer()
            return
    print(f"\n  {RE}Module not found: {mod_name!r}{R}")
    print(f"  {DM}Run:  python3 projectz.py --list-modules{R}\n")


def _print_section(section_key: str):
    """Print all modules in one section."""
    section_map = {
        "domain":     "DOMAIN INTELLIGENCE",
        "people":     "PEOPLE & OSINT",
        "network":    "NETWORK & INFRASTRUCTURE",
        "dorking":    "SEARCH ENGINE DORKING",
        "harvesting": "DATA HARVESTING",
        "cybersec":   "CYBERSEC & THREAT INTEL",
    }
    sec = section_map.get(section_key.lower())
    if not sec or sec not in MODULES:
        print(f"\n  {RE}Section not found: {section_key!r}{R}")
        return
    _header()
    print(f"  {M}{sec}{R}")
    for mod_name, mod_info in MODULES[sec].items():
        _print_module_block(mod_name, mod_info)
    _footer()
