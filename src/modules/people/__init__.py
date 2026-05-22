"""
ProjectZ - People Intelligence Modules (Phase 3)

Modules:
  emails      → Email harvesting — website scraping, GitHub commits, patterns
  phones      → Phone number discovery — website regex extraction
  linkedin    → LinkedIn profile discovery — Google/Bing dorks
  twitter     → Twitter/X handle discovery — meta tags, search dorks
  github      → GitHub OSINT — org members, repos, commit emails, secrets
  usernames   → Username enumeration across 40+ platforms
  breach      → Breach check — HIBP domain/email lookup
  employees   → Employee enumeration — LinkedIn dorks + GitHub members

Usage:
  python3 projectz tesla.com people.all
  python3 projectz tesla.com people.emails
  python3 projectz ceo@tesla.com people.breach
  python3 projectz elonmusk people.usernames
"""

from src.modules.people.emails         import EmailModule
from src.modules.people.phones         import PhoneModule
from src.modules.people.social_linkedin import LinkedInModule
from src.modules.people.social_twitter import TwitterModule
from src.modules.people.social_github  import GitHubModule
from src.modules.people.usernames      import UsernameModule
from src.modules.people.breach_check   import BreachModule
from src.modules.people.employee_enum  import EmployeeModule

__all__ = [
    "EmailModule", "PhoneModule", "LinkedInModule", "TwitterModule",
    "GitHubModule", "UsernameModule", "BreachModule", "EmployeeModule",
]
