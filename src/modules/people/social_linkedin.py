"""
ProjectZ - Module 13: LinkedIn Profile Enumeration
Public profile discovery via search scraping + Google dorks.
Self-coded — no LinkedIn API (uses dork-based discovery).
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


class LinkedInModule(BaseModule):
    MODULE_NAME = "linkedin"
    DESCRIPTION = "LinkedIn profile discovery — company employees via dorks + public search"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"LinkedIn OSINT: {target}")

        cached = cache.get("linkedin", target)
        if cached:
            return cached

        # Parallel: Google dork + Bing dork
        google_profiles, bing_profiles = await asyncio.gather(
            self._google_dork(target),
            self._bing_dork(target),
            return_exceptions=True,
        )

        if isinstance(google_profiles, Exception): google_profiles = []
        if isinstance(bing_profiles,  Exception):  bing_profiles   = []

        # Merge and deduplicate by URL
        all_profiles = self._merge_profiles(google_profiles + bing_profiles)

        # Extract metadata from profile URLs
        enriched = [self._enrich_profile(p) for p in all_profiles]

        result = {
            "target":       target,
            "profiles":     enriched,
            "total":        len(enriched),
            "company_url":  f"https://www.linkedin.com/company/{target.split('.')[0]}",
            "names":        [p.get("name", "") for p in enriched if p.get("name")],
            "titles":       [p.get("title", "") for p in enriched if p.get("title")],
            "sources": {
                "google_dork": len(google_profiles),
                "bing_dork":   len(bing_profiles),
            },
            "note": "LinkedIn blocks automated scraping — these are dork-discovered public profiles",
        }

        for p in enriched[:5]:
            self.log.found("LinkedIn Profile", p.get("name", p.get("url", "")))

        cache.set("linkedin", target, result)
        await self._persist_db(result)
        return result

    # ── Google dork ────────────────────────────────────────────────────────
    async def _google_dork(self, domain: str) -> list[dict]:
        company  = domain.split(".")[0]
        query    = f'site:linkedin.com/in "{company}"'
        url      = f"https://www.google.com/search?q={quote(query)}&num=20"
        return await self._scrape_search(url, "google")

    # ── Bing dork ─────────────────────────────────────────────────────────
    async def _bing_dork(self, domain: str) -> list[dict]:
        company = domain.split(".")[0]
        query   = f'site:linkedin.com/in "{company}"'
        url     = f"https://www.bing.com/search?q={quote(query)}&count=20"
        return await self._scrape_search(url, "bing")

    # ── Generic search scraper ─────────────────────────────────────────────
    async def _scrape_search(self, url: str, source: str) -> list[dict]:
        profiles = []
        host     = url.split("/")[2]
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                profiles = self._extract_li_urls(html, source)
        except Exception as e:
            self.log.warning(f"{source} dork error: {e}")
        return profiles

    # ── Extract LinkedIn URLs from HTML ────────────────────────────────────
    def _extract_li_urls(self, html: str, source: str) -> list[dict]:
        profiles = []
        # Match LinkedIn profile URLs
        pattern = re.compile(
            r"https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9\-_%]+)/?",
            re.IGNORECASE,
        )
        seen = set()
        for m in pattern.finditer(html):
            slug = m.group(1)
            url  = f"https://www.linkedin.com/in/{slug}"
            if slug not in seen:
                seen.add(slug)
                # Try to extract name from surrounding text
                start  = max(0, m.start() - 150)
                end    = min(len(html), m.end() + 150)
                ctx    = re.sub(r"<[^>]+>", " ", html[start:end])
                ctx    = re.sub(r"\s+", " ", ctx).strip()
                profiles.append({"url": url, "slug": slug, "context": ctx, "source": source})
        return profiles

    # ── Merge + deduplicate ────────────────────────────────────────────────
    def _merge_profiles(self, profiles: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for p in profiles:
            if p["slug"] not in seen:
                seen.add(p["slug"])
                clean.append(p)
        return clean

    # ── Enrich with name/title guesses ────────────────────────────────────
    def _enrich_profile(self, profile: dict) -> dict:
        ctx   = profile.get("context", "")
        slug  = profile.get("slug", "")

        # Guess name from slug (firstname-lastname format)
        name = ""
        m    = re.match(r"^([a-z]+)-([a-z]+)(?:-\d+)?$", slug)
        if m:
            name = f"{m.group(1).title()} {m.group(2).title()}"

        # Extract title from context
        title = ""
        title_patterns = [
            r"(?:at|@)\s+\w+\s+-\s+([^|·•]+)",
            r"([A-Z][a-z]+ (?:Manager|Director|Engineer|Developer|Analyst|Lead|Head|VP|CTO|CEO)[^|·•]*)",
        ]
        for pat in title_patterns:
            tm = re.search(pat, ctx)
            if tm:
                title = tm.group(1).strip()[:80]
                break

        return {
            "url":    profile["url"],
            "slug":   slug,
            "name":   name,
            "title":  title,
            "source": profile["source"],
        }


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
