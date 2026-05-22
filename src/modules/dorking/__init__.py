"""
ProjectZ - Dorking Modules (Phase 5)

Modules:
  files     → Sensitive file exposure — configs, backups, DB dumps, keys (Bing dorks)
  admin     → Admin panel discovery — wordlist probe + login page detection + dorks
  errors    → Error/info disclosure — stack traces, DB errors, path disclosure (Bing dorks)
  creds     → Credential exposure — API keys, passwords, tokens, DB strings (Bing + GitHub)
  vulns     → Vulnerability dorks — SQLi params, exposed services, CMS vulns (Bing dorks)
  dirbust   → Directory brute-force — async HTTP probe, title extraction, sensitive detection

Usage:
  python3 projectz tesla.com dorking.all
  python3 projectz tesla.com dorking.admin
  python3 projectz tesla.com dorking.creds
  python3 projectz tesla.com dorking.dirbust
  python3 projectz tesla.com dorking.vulns,dorking.errors
"""

from src.modules.dorking.files_enum      import FilesEnumModule
from src.modules.dorking.admin_panels    import AdminPanelModule
from src.modules.dorking.error_messages  import ErrorMsgModule
from src.modules.dorking.credentials     import CredentialsModule
from src.modules.dorking.vulns_dorks     import VulnsDorksModule
from src.modules.dorking.directory_brute import DirBruteModule

__all__ = [
    "FilesEnumModule", "AdminPanelModule", "ErrorMsgModule",
    "CredentialsModule", "VulnsDorksModule", "DirBruteModule",
]
