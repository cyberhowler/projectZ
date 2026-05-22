from __future__ import annotations
"""
ProjectZ - Module 10: Email Harvesting
Regex scraping + GitHub commits + common pattern generation.
Self-coded — no paid APIs.
"""

import asyncio
import re
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# Email regex — RFC-compliant, no catastrophic backtracking
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,10}",
    re.IGNORECASE,
)

# Common corporate email patterns
_PATTERNS = [
    "{first}.{last}",
    "{first}{last}",
    "{f}{last}",
    "{first}",
    "{last}",
    "{first}_{last}",
    "{f}.{last}",
]


class EmailModule(BaseModule):
    MODULE_NAME = "emails"
    DESCRIPTION = "Email harvesting — regex scraping, GitHub commits, pattern generation"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"Email harvesting: {target}")

        cached = cache.get("emails", target)
        if cached:
            return cached

        found: set[str] = set()

        # 1. Scrape target website
        web_emails = await self._scrape_website(target)
        found.update(web_emails)

        # 2. GitHub commit history
        github_emails = await self._github_commits(target)
        found.update(github_emails)

        # 3. Generate common patterns (needs names — placeholder for employee_enum integration)
        pattern_emails = self._generate_patterns(target)
        found.update(pattern_emails)

        # Filter to only emails belonging to this domain
        domain_emails = {e for e in found if e.lower().endswith(f"@{target}")}
        all_emails    = list(found)

        # Store in DB
        for email in domain_emails:
            await DatabaseManager.insert_email(email, target, "email_module")

        result = {
            "domain":         target,
            "total":          len(domain_emails),
            "emails":         sorted(domain_emails),
            "all_emails":     sorted(all_emails),
            "domain_emails":  len(domain_emails),
            "total_found":    len(all_emails),
            "sources": {
                "website": len(web_emails),
                "github":  len(github_emails),
                "patterns": len(pattern_emails),
            },
        }

        for e in sorted(domain_emails)[:10]:
            self.log.found("Email", e)

        cache.set("emails", target, result)
        return result

    # ── Website scraper ────────────────────────────────────────────────────
    async def _scrape_website(self, domain: str) -> set[str]:
        emails: set[str] = set()
        urls_to_check = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/team",
            f"https://{domain}/about-us",
            f"https://{domain}/contact-us",
        ]
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            tasks = [self._fetch_emails(session, url) for url in urls_to_check]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, set):
                    emails.update(r)
        return emails

    async def _fetch_emails(self, session, url: str) -> set[str]:
        try:
            async with rate_limiter.throttle(url.split("/")[2]):
                async with session.get(url, headers=config.DEFAULT_HEADERS,
                                       allow_redirects=True) as resp:
                    if resp.status < 400:
                        text = await resp.text(errors="ignore")
                        return set(_EMAIL_RE.findall(text))
        except Exception:
            pass
        return set()

    # ── GitHub commit emails (FREE API) ────────────────────────────────────
    async def _github_commits(self, domain: str) -> set[str]:
        """Search GitHub for commits referencing this domain."""
        emails: set[str] = set()
        headers = {**config.DEFAULT_HEADERS}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"

        # Search for recent commits with domain in email
        url = f"https://api.github.com/search/commits?q={domain}&per_page=30"
        try:
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                for item in data.get("items", []):
                    commit  = item.get("commit", {})
                    author  = commit.get("author", {})
                    c_email = author.get("email", "")
                    if c_email and "@" in c_email:
                        emails.add(c_email.lower())
        except Exception as e:
            self.log.warning(f"GitHub commits error: {e}")
        return emails

    # ── Pattern generation ─────────────────────────────────────────────────
    def _generate_patterns(self, domain: str) -> set[str]:
        """Generate common email format guesses from domain name."""
        emails: set[str] = set()
        # Common generic addresses
        for prefix in ["info", "contact", "hello", "support", "admin", "sales",
                        "hr", "jobs", "press", "media", "legal", "security",
                        "abuse", "privacy", "help", "team", "marketing"]:
            emails.add(f"{prefix}@{domain}")
        return emails

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
