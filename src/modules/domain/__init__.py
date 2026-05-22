"""
ProjectZ - Domain Intelligence Modules (Phase 2)

Modules:
  whois       → Registrar, dates, nameservers, registrant
  dns         → A/AAAA/MX/TXT/NS/CNAME/SOA/CAA records
  subdomains  → crt.sh CT logs + wordlist bruteforce + DNS validation
  ssl         → Certificate analysis, SANs, CT logs, cipher suites
  tech        → Technology fingerprinting (CMS/framework/server/CDN)
  asn         → ASN/BGP mapping, country, prefixes
  hosting     → Cloud provider detection (AWS/GCP/Azure/Cloudflare)
  reverseip   → Virtual host enumeration, co-hosted domains
  spfdmarc    → SPF/DMARC/DKIM/MTA-STS email security posture

Usage (dot-notation):
  python3 projectz tesla.com domain.all
  python3 projectz tesla.com domain.whois
  python3 projectz tesla.com domain.whois,domain.dns
"""

from src.modules.domain.whois       import WhoisModule
from src.modules.domain.dns_records import DNSModule
from src.modules.domain.subdomains  import SubdomainModule
from src.modules.domain.ssl_certs   import SSLModule
from src.modules.domain.tech_stack  import TechStackModule
from src.modules.domain.asn_info    import ASNModule
from src.modules.domain.hosting     import HostingModule
from src.modules.domain.reverse_ip  import ReverseIPModule
from src.modules.domain.spf_dmarc   import SPFDMARCModule

__all__ = [
    "WhoisModule", "DNSModule", "SubdomainModule", "SSLModule",
    "TechStackModule", "ASNModule", "HostingModule",
    "ReverseIPModule", "SPFDMARCModule",
]
