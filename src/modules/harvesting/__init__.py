"""
ProjectZ - Harvesting Modules (Phase 6)

Modules:
  google   → Google OSINT harvester — 60+ dorks, 8 categories, risk tagging, auto-pagination
  bing     → Bing OSINT harvester — 50+ dorks, auto-pagination, subdomain mining, risk scoring
  crtsh    → Certificate Transparency — crt.sh + certspotter, subdomain intel, cert timeline
  dnsdump  → Full DNS harvest — DNSDumpster, zone transfer, DoH fallback, all record types
  leaks    → Data leak harvester — HIBP, paste sites, GitHub gists, breach intelligence
  histdns  → Historical DNS — Wayback, CIRCL passive DNS, VirusTotal, IP change tracking
  hunter   → Email intelligence — pattern gen, SMTP verify, Gravatar, GitHub mining, confidence scores

Usage:
  python3 projectz tesla.com harvesting.all
  python3 projectz tesla.com harvesting.google,harvesting.bing
  python3 projectz tesla.com harvesting.crtsh
  python3 projectz tesla.com harvesting.dnsdump
  python3 projectz tesla.com harvesting.leaks
  python3 projectz tesla.com harvesting.histdns
  python3 projectz tesla.com harvesting.hunter
"""

from src.modules.harvesting.google_harvest       import GoogleHarvestModule
from src.modules.harvesting.bing_harvest         import BingHarvestModule
from src.modules.harvesting.crtsh                import CRTShModule
from src.modules.harvesting.dnsdumpster          import DNSDumpsterModule
from src.modules.harvesting.leakcheck            import LeakCheckModule
from src.modules.harvesting.securitytrails_alt   import HistDNSModule
from src.modules.harvesting.hunter_alt           import HunterAltModule

__all__ = [
    "GoogleHarvestModule", "BingHarvestModule", "CRTShModule",
    "DNSDumpsterModule", "LeakCheckModule", "HistDNSModule", "HunterAltModule",
]
