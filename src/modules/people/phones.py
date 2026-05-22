from __future__ import annotations
"""
ProjectZ - Module 11: Phone Number Discovery
Scrape target website + Google dorks for phone numbers.
Self-coded regex-based — no paid APIs.
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

# International phone regex patterns
_PHONE_PATTERNS = [
    # +1 (555) 555-5555 / +1-555-555-5555
    re.compile(r"\+?1[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"),
    # +44 20 7946 0958 (UK)
    re.compile(r"\+44[\s\-.]?\d{2,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}"),
    # General international: +XX XXXXXXXXXX
    re.compile(r"\+\d{1,3}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}[\s\-.]?\d{0,4}"),
    # Indian: +91 XXXXX XXXXX
    re.compile(r"\+91[\s\-.]?\d{5}[\s\-.]?\d{5}"),
    # Generic 10-digit
    re.compile(r"\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"),
]

_MIN_DIGITS = 7   # discard strings with fewer digits


class PhoneModule(BaseModule):
    MODULE_NAME = "phones"
    DESCRIPTION = "Phone number harvesting — website scraping + regex extraction"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"Phone harvesting: {target}")

        cached = cache.get("phones", target)
        if cached:
            return cached

        found: set[str] = set()

        # Scrape website pages
        web_phones = await self._scrape_website(target)
        found.update(web_phones)

        # Normalise and deduplicate
        normalised = {self._normalise(p) for p in found}
        normalised = {p for p in normalised if self._valid(p)}

        # Store in DB via the existing insert_finding helper
        if normalised:
            await DatabaseManager.insert_finding(
                target=target,
                module="phones",
                title=f"Phone numbers found: {', '.join(sorted(normalised)[:5])}",
                severity="info",
                evidence=str(sorted(normalised)),
            )

        result = {
            "domain":      target,
            "phones":      sorted(normalised),
            "raw_found":   sorted(found),
            "total":       len(normalised),
            "sources":     {"website": len(web_phones)},
        }

        for p in sorted(normalised)[:8]:
            self.log.found("Phone", p)

        cache.set("phones", target, result)
        return result

    # ── Website scraper ────────────────────────────────────────────────────
    async def _scrape_website(self, domain: str) -> set[str]:
        phones: set[str] = set()
        urls = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/contact-us",
            f"https://{domain}/support",
        ]
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            sem = asyncio.Semaphore(5)
            results = await asyncio.gather(
                *[self._fetch_phones(session, url) for url in urls],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, set):
                    phones.update(r)
        return phones

    async def _fetch_phones(self, session, url: str) -> set[str]:
        found: set[str] = set()
        try:
            async with rate_limiter.throttle(url.split("/")[2]):
                async with session.get(url, headers=config.DEFAULT_HEADERS,
                                       allow_redirects=True) as resp:
                    if resp.status < 400:
                        text = await resp.text(errors="ignore")
                        # Strip HTML tags for cleaner matching
                        text = re.sub(r"<[^>]+>", " ", text)
                        for pattern in _PHONE_PATTERNS:
                            matches = pattern.findall(text)
                            found.update(matches)
        except Exception:
            pass
        return found

    # ── Normalise number ───────────────────────────────────────────────────
    def _normalise(self, phone: str) -> str:
        """Strip formatting, keep digits and leading +."""
        digits = re.sub(r"[^\d+]", "", phone)
        return digits

    def _valid(self, phone: str) -> bool:
        """Reject strings with too few digits or obvious false positives."""
        digits_only = re.sub(r"\D", "", phone)
        if len(digits_only) < _MIN_DIGITS:
            return False
        # Skip version numbers like 1.0.0 → "100"
        if len(digits_only) < 7:
            return False
        return True

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
