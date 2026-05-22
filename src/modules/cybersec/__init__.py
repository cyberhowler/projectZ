"""
ProjectZ - Cybersec Modules (Phase 7)

12 modules covering full threat intelligence lifecycle:

  virustotal  -> Multi-engine URL/IP/domain reputation (VT, URLVoid, PhishTank, Sucuri)
  urlscan     -> URL scan (urlscan.io, Wayback screenshots, DOM malware patterns)
  yara        -> YARA-style malware scanner (50+ rules, webshells, miners, C2, obfuscation)
  threatcrowd -> IOC engine (ThreatFox, OTX, GreyNoise, CVE data, IOC extraction)
  abuseipdb   -> IP abuse intel (AbuseIPDB, GreyNoise, 10 DNSBL zones, BGP Ranking)
  otx         -> AlienVault OTX (pulses, IOC pivot, passive DNS, ATT&CK TTPs)
  intelx      -> Dark web intel (IntelX, Ahmia Tor, ransomware feeds, paste aggregators)
  hibp        -> HIBP breach intel (domain/email/password, severity scoring, timeline)
  pastebin    -> Live paste monitor (credential dumps, API key leaks, IOC extraction)
  exploitdb   -> CVE/exploit intel (NVD, CIRCL, EPSS scoring, CISA KEV, PoC detection)
  urlhaus     -> URLhaus malware URLs (host lookup, payload hashes, botnet C2, live feed)
  packetstorm -> Exploit archive (Packetstorm, Sploitus, Vulners, maturity scoring)

Usage:
  python3 projectz tesla.com cybersec.all
  python3 projectz 1.2.3.4 cybersec.abuseipdb,cybersec.otx,cybersec.threatcrowd
  python3 projectz CVE-2021-44228 cybersec.exploitdb,cybersec.packetstorm
  python3 projectz admin@tesla.com cybersec.hibp
  python3 projectz tesla.com cybersec.virustotal,cybersec.urlscan,cybersec.yara
"""

from src.modules.cybersec.virustotal_alt   import VTAltModule
from src.modules.cybersec.urlscanio_alt    import URLScanModule
from src.modules.cybersec.hybrid_alt       import YARAModule
from src.modules.cybersec.threatcrowd_alt  import ThreatCrowdModule
from src.modules.cybersec.abuseipdb_alt    import AbuseIPDBModule
from src.modules.cybersec.otx_alt          import OTXModule
from src.modules.cybersec.intelx_alt       import IntelXModule
from src.modules.cybersec.haveibeenpwned   import HIBPModule
from src.modules.cybersec.pastebin_dump    import PastebinModule
from src.modules.cybersec.exploitdb        import ExploitDBModule
from src.modules.cybersec.urlhaus          import URLHausModule
from src.modules.cybersec.packetstorm      import PacketstormModule

__all__ = [
    "VTAltModule", "URLScanModule", "YARAModule", "ThreatCrowdModule",
    "AbuseIPDBModule", "OTXModule", "IntelXModule", "HIBPModule",
    "PastebinModule", "ExploitDBModule", "URLHausModule", "PacketstormModule",
]

# Five Eyes module added
from src.modules.cybersec.fiveeyes import FiveEyesModule
