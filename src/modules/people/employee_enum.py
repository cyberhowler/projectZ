"""
ProjectZ - Module 17: Employee Enumeration
Discover company staff via LinkedIn dorks, GitHub org members,
website scraping, and email pattern generation.
Self-coded — no paid APIs.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class EmployeeModule(BaseModule):
    MODULE_NAME = "employees"
    DESCRIPTION = "Employee enumeration — LinkedIn dorks, GitHub members, website scraping"

    async def run(self) -> dict:
        domain  = self._clean(self.target)
        company = domain.split(".")[0]
        self.log.info(f"Employee enumeration: {domain} ({company})")

        cached = cache.get("employees", domain)
        if cached:
            return cached

        # Parallel discovery
        li_people, gh_members, web_people = await asyncio.gather(
            self._linkedin_dork(company, domain),
            self._github_members(company),
            self._scrape_team_page(domain),
            return_exceptions=True,
        )

        if isinstance(li_people,  Exception): li_people  = []
        if isinstance(gh_members, Exception): gh_members = []
        if isinstance(web_people, Exception): web_people = []

        # Merge and deduplicate by name
        all_people = self._merge_people(li_people + web_people)

        # Generate email patterns for discovered names
        email_patterns = self._generate_emails(all_people, domain)

        result = {
            "domain":          domain,
            "company":         company,
            "employees":       all_people,
            "total":           len(all_people),
            "github_members":  gh_members,
            "email_patterns":  email_patterns,
            "sources": {
                "linkedin_dork": len(li_people),
                "github":        len(gh_members),
                "website":       len(web_people),
            },
        }

        for person in all_people[:5]:
            self.log.found("Employee", f"{person.get('name','')} — {person.get('title','')}")

        cache.set("employees", domain, result)
        return result

    # ── LinkedIn dork via Google/Bing ──────────────────────────────────────
    async def _linkedin_dork(self, company: str, domain: str) -> list[dict]:
        people = []
        queries = [
            f'site:linkedin.com/in "{company}"',
            f'site:linkedin.com/in "@{domain}"',
        ]
        for query in queries:
            url   = f"https://www.bing.com/search?q={quote(query)}&count=30"
            batch = await self._search_people(url, "bing_linkedin")
            people.extend(batch)
        return people

    async def _search_people(self, url: str, source: str) -> list[dict]:
        people = []
        host   = url.split("/")[2]
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                people = self._extract_from_li_html(html, source)
        except Exception as e:
            self.log.warning(f"Dork error ({source}): {e}")
        return people

    def _extract_from_li_html(self, html: str, source: str) -> list[dict]:
        people = []
        seen   = set()
        # Match LinkedIn profile URLs
        pattern = re.compile(
            r"linkedin\.com/in/([a-zA-Z0-9\-_]+)/?\s*[–-]\s*([^<\n|]{5,80})",
            re.IGNORECASE,
        )
        for m in pattern.finditer(html):
            slug = m.group(1).lower()
            ctx  = re.sub(r"\s+", " ", m.group(2)).strip()
            if slug in seen:
                continue
            seen.add(slug)

            name  = self._slug_to_name(slug)
            title = ctx[:80] if ctx else ""

            people.append({
                "name":       name,
                "slug":       slug,
                "title":      title,
                "linkedin":   f"https://www.linkedin.com/in/{slug}",
                "source":     source,
            })
        return people

    def _slug_to_name(self, slug: str) -> str:
        """Convert linkedin-slug to 'First Last'."""
        m = re.match(r"^([a-z]+)[_-]([a-z]+)", slug)
        if m:
            return f"{m.group(1).title()} {m.group(2).title()}"
        return slug.replace("-", " ").replace("_", " ").title()

    # ── GitHub org members ─────────────────────────────────────────────────
    async def _github_members(self, company: str) -> list[str]:
        url     = f"https://api.github.com/orgs/{company}/members?per_page=100"
        headers = {**config.DEFAULT_HEADERS, "Accept": "application/vnd.github.v3+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                return [m.get("login", "") for m in data if m.get("login")]
        except Exception as e:
            self.log.warning(f"GitHub members error: {e}")
        return []

    # ── Team/About page scraper ────────────────────────────────────────────
    async def _scrape_team_page(self, domain: str) -> list[dict]:
        people = []
        urls   = [
            f"https://{domain}/team",
            f"https://{domain}/about",
            f"https://{domain}/about-us",
            f"https://{domain}/people",
            f"https://{domain}/leadership",
            f"https://{domain}/our-team",
        ]
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            _sem = asyncio.Semaphore(20)
            async def _bounded(u):
                async with _sem:
                    return await self._fetch_team(u)
            results = await asyncio.gather(
                *[_bounded(url) for url in urls],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    people.extend(r)
        return people

    async def _fetch_team(self, url: str) -> list[dict]:
        people = []
        try:
            async with rate_limiter.throttle(url.split("/")[2]):
                _r = await fetch(url, headers=config.DEFAULT_HEADERS,
                                       allow_redirects=True, timeout=8)
                if _r["ok"]:
                    html  = _r["text"]
                    text  = re.sub(r"<[^>]+>", " ", html)
                    text  = re.sub(r"\s+", " ", text)
                    people = self._extract_names_from_text(text, url)
        except Exception:
            pass
        return people

    def _extract_names_from_text(self, text: str, source_url: str) -> list[dict]:
        """Extract probable person names: 'First Last' capitalised pairs."""
        pattern = re.compile(r"\b([A-Z][a-z]{2,15})\s+([A-Z][a-z]{2,20})\b")
        # Common false-positive words to skip
        skip    = {"About Us", "Our Team", "Read More", "Learn More", "View All",
                   "Privacy Policy", "Terms Of", "All Rights", "Cookie Policy"}
        people  = []
        seen    = set()
        for m in pattern.finditer(text):
            name = f"{m.group(1)} {m.group(2)}"
            if name not in skip and name not in seen:
                seen.add(name)
                people.append({"name": name, "source": source_url, "title": ""})
        return people[:30]   # cap per page

    # ── Email pattern generation ───────────────────────────────────────────
    def _generate_emails(self, people: list[dict], domain: str) -> list[str]:
        emails = []
        for person in people[:20]:
            name  = person.get("name", "")
            parts = name.lower().split()
            if len(parts) < 2:
                continue
            first, last = parts[0], parts[-1]
            f           = first[0]
            for pattern in [
                f"{first}.{last}@{domain}",
                f"{first}{last}@{domain}",
                f"{f}{last}@{domain}",
                f"{first}@{domain}",
            ]:
                emails.append(pattern)
        return sorted(set(emails))

    # ── Merge + dedup ──────────────────────────────────────────────────────
    def _merge_people(self, people: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for p in people:
            key = p.get("name", "").lower().strip()
            if key and key not in seen:
                seen.add(key)
                clean.append(p)
        return clean

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
