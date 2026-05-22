from __future__ import annotations
"""
ProjectZ - Module 14: Twitter/X Handle Discovery
Find Twitter handles linked to a domain — via website scraping,
meta tags, Google dorks. Self-coded, no Twitter API required.
"""

import asyncio
import re
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# Twitter/X handle regex
_HANDLE_RE  = re.compile(r"(?:twitter\.com|x\.com)/(@?[A-Za-z0-9_]{1,50})", re.IGNORECASE)
_AT_HANDLE  = re.compile(r'(?:content|href)=["\']?@([A-Za-z0-9_]{2,50})["\']?', re.IGNORECASE)
_META_TWITTER = re.compile(
    r'<meta[^>]+(?:name|property)=["\']twitter:(?:site|creator)["\'][^>]*content=["\']@?([A-Za-z0-9_]+)["\']',
    re.IGNORECASE,
)

# Known fake/generic handles to skip
_SKIP = {"twitter", "share", "intent", "home", "search", "explore", "notifications",
         "messages", "i", "settings", "hashtag", "compose", "web", "status"}


class TwitterModule(BaseModule):
    MODULE_NAME = "twitter"
    DESCRIPTION = "Twitter/X handle discovery — meta tags, website scraping, search dorks"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"Twitter OSINT: {target}")

        cached = cache.get("twitter", target)
        if cached:
            return cached

        handles: set[str] = set()

        # 1. Scrape website for Twitter links
        web_handles = await self._scrape_website(target)
        handles.update(web_handles)

        # 2. Google dork for Twitter handles linked to domain
        dork_handles = await self._google_dork(target)
        handles.update(dork_handles)

        # Clean handles
        clean = {h.lstrip("@").lower() for h in handles
                 if h.lstrip("@").lower() not in _SKIP and len(h) >= 2}

        result = {
            "target":      target,
            "handles":     sorted(clean),
            "total":       len(clean),
            "profile_urls": [f"https://x.com/{h}" for h in sorted(clean)],
            "sources": {
                "website_scrape": len(web_handles),
                "google_dork":    len(dork_handles),
            },
        }

        for h in sorted(clean)[:5]:
            self.log.found("Twitter Handle", f"@{h} → https://x.com/{h}")

        cache.set("twitter", target, result)
        await self._persist_db(result)
        return result

    # ── Website scraper ────────────────────────────────────────────────────
    async def _scrape_website(self, domain: str) -> set[str]:
        handles: set[str] = set()
        urls = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
        ]
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=12),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            sem = asyncio.Semaphore(5)
            results = await asyncio.gather(
                *[self._fetch_handles(session, url) for url in urls],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, set):
                    handles.update(r)
        return handles

    async def _fetch_handles(self, session, url: str) -> set[str]:
        found: set[str] = set()
        try:
            async with rate_limiter.throttle(url.split("/")[2]):
                async with session.get(url, headers=config.DEFAULT_HEADERS,
                                       allow_redirects=True) as resp:
                    if resp.status == 200:
                        html = await resp.text(errors="ignore")
                        # Meta twitter:site / twitter:creator
                        for m in _META_TWITTER.finditer(html):
                            found.add(m.group(1))
                        # twitter.com/handle links
                        for m in _HANDLE_RE.finditer(html):
                            found.add(m.group(1).lstrip("@"))
        except Exception:
            pass
        return found

    # ── Google dork ────────────────────────────────────────────────────────
    async def _google_dork(self, domain: str) -> set[str]:
        query = f'site:twitter.com OR site:x.com "{domain}"'
        url   = f"https://www.google.com/search?q={quote(query)}&num=15"
        found: set[str] = set()
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                for m in _HANDLE_RE.finditer(html):
                    found.add(m.group(1).lstrip("@"))
        except Exception as e:
            self.log.warning(f"Google dork error: {e}")
        return found


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
