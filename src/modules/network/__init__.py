"""
ProjectZ - Network Intelligence Modules (Phase 4)

Modules:
  geo        → IP/domain geolocation — country, city, ISP, coordinates
  iprep      → IP reputation — AbuseIPDB, OTX, URLhaus, GreyNoise
  portscan   → Port scanner — nmap (if installed) or async TCP connect fallback
  masscan    → High-speed masscan — falls back to async TCP connect
  shodan     → Internet device discovery — Shodan public + Criminal IP
  censys     → Internet scan intel — Shodan InternetDB (free) + Censys + FOFA
  banner     → Service banner grabbing — raw socket + HTTP title extraction
  zoomeye    → Network intel aggregator — InternetDB + HackerTarget + HE BGP

Usage:
  python3 projectz tesla.com network.all
  python3 projectz 8.8.8.8 network.geo,network.iprep
  python3 projectz tesla.com network.portscan
  python3 projectz 1.1.1.1 network.censys
"""

from src.modules.network.geolocation  import GeoModule
from src.modules.network.ip_reputation import IPReputationModule
from src.modules.network.nmap_wrapper  import NmapModule
from src.modules.network.masscan       import MasscanModule
from src.modules.network.shodan_alt    import ShodanAltModule
from src.modules.network.censys_alt    import CensysAltModule
from src.modules.network.onyphe_alt    import BannerModule
from src.modules.network.zoomeye_alt   import ZoomEyeModule

__all__ = [
    "GeoModule", "IPReputationModule", "NmapModule", "MasscanModule",
    "ShodanAltModule", "CensysAltModule", "BannerModule", "ZoomEyeModule",
]
