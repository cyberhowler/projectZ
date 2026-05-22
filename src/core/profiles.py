"""
ProjectZ - Scan Profile System
Save named scan templates as YAML/JSON files in data/profiles/.
Usage:
  python3 projectz.py tesla.com --profile pentest
  python3 projectz.py 8.8.8.8  --profile quick_ip
  python3 projectz.py --list-profiles

Built-in profiles:
  quick         7 modules  — fast recon, no auth needed
  full          50 modules — everything
  pentest       all recon + creds/admin/vulns
  domain        all domain modules
  osint         people + social + breaches
  threat_intel  cybersec + network intel
  quick_ip      geo + iprep + threat intel for IP targets
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

_profiles_dir = Path(__file__).resolve().parents[2] / "data" / "profiles"
_profiles_dir.mkdir(parents=True, exist_ok=True)

# ── Built-in profiles ─────────────────────────────────────────────────────
BUILTIN_PROFILES: dict[str, dict] = {
    "quick": {
        "name": "quick",
        "description": "Fast 7-module recon — no API keys required",
        "modules": ["whois", "dns", "subdomains", "ssl", "emails", "tech", "geo"],
        "options": {"max_workers": 7},
    },
    "full": {
        "name": "full",
        "description": "All 56 modules — comprehensive scan",
        "modules": ["full"],
        "options": {"max_workers": 15},
    },
    "pentest": {
        "name": "pentest",
        "description": "Full recon + vulnerability hints for pentest engagements",
        "modules": [
            "whois", "dns", "subdomains", "ssl", "tech", "asn", "hosting", "spfdmarc",
            "emails", "employees", "breach", "github",
            "portscan", "geo", "iprep", "shodan", "censys",
            "google", "bing", "crtsh",
            "admin", "creds", "vulns", "errors", "files",
            "virustotal", "otx", "abuseipdb",
        ],
        "options": {"max_workers": 15},
    },
    "domain": {
        "name": "domain",
        "description": "All domain-focused modules",
        "modules": ["whois", "dns", "subdomains", "ssl", "tech", "asn", "hosting", "spfdmarc", "reverseip"],
        "options": {"max_workers": 9},
    },
    "osint": {
        "name": "osint",
        "description": "People intelligence, social, breach checks",
        "modules": ["emails", "phones", "linkedin", "twitter", "github", "usernames", "breach", "employees", "hunter"],
        "options": {"max_workers": 9},
    },
    "threat_intel": {
        "name": "threat_intel",
        "description": "Cybersecurity and threat intelligence modules",
        "modules": ["virustotal", "urlscan", "hibp", "otx", "abuseipdb", "urlhaus", "intelx", "yara", "threatcrowd", "fiveeyes"],
        "options": {"max_workers": 9},
    },
    "quick_ip": {
        "name": "quick_ip",
        "description": "Fast IP intelligence — geo, reputation, threat feeds",
        "modules": ["geo", "iprep", "abuseipdb", "otx", "shodan", "censys"],
        "options": {"max_workers": 6},
    },
    "recon": {
        "name": "recon",
        "description": "Classic recon workflow — domain + people + harvesting",
        "modules": [
            "whois", "dns", "subdomains", "ssl", "tech",
            "emails", "employees",
            "google", "bing", "crtsh", "dnsdump",
        ],
        "options": {"max_workers": 10},
    },
    "red_team": {
        "name": "red_team",
        "description": "Full red team pre-engagement recon — all attack surface modules",
        "modules": [
            # Infrastructure
            "whois", "dns", "subdomains", "ssl", "tech", "asn", "hosting", "spfdmarc",
            # Web attack surface
            "waf", "headers", "cors", "cms",
            # Network
            "portscan", "masscan", "geo", "iprep", "shodan", "censys",
            # People / Social Engineering
            "emails", "phones", "employees", "linkedin", "github", "breach",
            # Credential exposure
            "creds", "admin", "files", "vulns", "errors",
            # Cloud
            "s3buckets",
            # Threat Intel
            "virustotal", "otx", "abuseipdb", "urlhaus", "exploitdb",
            # Harvesting
            "google", "bing", "crtsh", "dnsdump", "leaks", "hunter",
        ],
        "options": {"max_workers": 20},
    },
    "bug_bounty": {
        "name": "bug_bounty",
        "description": "Bug bounty recon — subdomain takeover, open buckets, CORS, misconfigs",
        "modules": [
            "whois", "dns", "subdomains", "ssl", "tech",
            "waf", "headers", "cors", "cms",
            "crtsh", "dnsdump", "histdns", "s3buckets",
            "admin", "files", "vulns", "errors",
            "virustotal", "urlscan", "shodan",
            "emails", "github",
        ],
        "options": {"max_workers": 15},
    },
    "passive_recon": {
        "name": "passive_recon",
        "description": "100%% passive recon — no direct target contact, OPSEC safe",
        "modules": [
            "whois", "dns", "ssl", "asn",
            "crtsh", "histdns", "dnsdump",
            "virustotal", "urlscan", "otx", "shodan", "censys", "zoomeye",
            "emails", "breach", "hibp",
            "pastebin", "intelx", "threatcrowd",
            "google", "bing",
        ],
        "options": {"max_workers": 10},
    },
    "web_audit": {
        "name": "web_audit",
        "description": "Web security audit — headers, CORS, WAF, CMS, admin panels, dorks",
        "modules": [
            "waf", "headers", "cors", "cms", "ssl", "tech",
            "admin", "files", "errors", "creds", "vulns", "dirbust",
            "virustotal", "urlscan",
        ],
        "options": {"max_workers": 10},
    },
    "social_eng": {
        "name": "social_eng",
        "description": "Social engineering prep — people intel, emails, breaches, social profiles",
        "modules": [
            "emails", "phones", "employees", "linkedin", "twitter", "github",
            "usernames", "breach", "hibp", "pastebin", "hunter", "leaks",
        ],
        "options": {"max_workers": 10},
    },
}


class ProfileManager:

    @staticmethod
    def get(name: str) -> Optional[dict]:
        """Return profile by name. Checks built-ins first, then data/profiles/."""
        if name in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[name]
        # Check file-based profiles
        for ext in (".json", ".yaml", ".yml"):
            p = _profiles_dir / f"{name}{ext}"
            if p.exists():
                try:
                    return json.loads(p.read_text())
                except Exception:
                    pass
        return None

    @staticmethod
    def save(name: str, modules: list[str], description: str = "",
             options: dict = None) -> str:
        """Save a custom profile to disk."""
        profile = {
            "name":        name,
            "description": description,
            "modules":     modules,
            "options":     options or {},
        }
        path = _profiles_dir / f"{name}.json"
        path.write_text(json.dumps(profile, indent=2))
        return str(path)

    @staticmethod
    def list_all() -> list[dict]:
        """List all profiles (built-in + user-saved)."""
        profiles = list(BUILTIN_PROFILES.values())
        for f in _profiles_dir.glob("*.json"):
            try:
                p = json.loads(f.read_text())
                if p.get("name") and p["name"] not in BUILTIN_PROFILES:
                    profiles.append(p)
            except Exception:
                pass
        return profiles

    @staticmethod
    def print_all():
        """Print profile listing to console."""
        from colorama import Fore, Style
        profiles = ProfileManager.list_all()
        print(f"\n{Fore.CYAN}  Available Profiles ({len(profiles)}):{Style.RESET_ALL}\n")
        for p in profiles:
            mods = p.get("modules", [])
            mod_count = len(mods) if mods != ["full"] else 56
            print(f"  {Fore.YELLOW}{p['name']:<18}{Style.RESET_ALL}"
                  f"{p.get('description',''):<55}"
                  f"{Fore.WHITE}({mod_count} modules){Style.RESET_ALL}")
        print()
