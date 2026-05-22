"""
ProjectZ - Module 16: Breach / Credential Leak Check
Check email/domain against HIBP API + public breach databases.
Uses FREE HIBP v3 API (requires API key for per-email checks).
Domain-level check is FREE and keyless.
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class BreachModule(BaseModule):
    MODULE_NAME = "breach"
    DESCRIPTION = "Breach check — HIBP domain/email lookup, breach metadata"

    async def run(self) -> dict:
        target = self.target.strip()
        self.log.info(f"Breach check: {target}")

        cached = cache.get("breach", target)
        if cached:
            return cached

        is_email  = "@" in target
        is_domain = not is_email and "." in target

        results = {}

        if is_email:
            results = await self._check_email(target)
        elif is_domain:
            # Check common email patterns for this domain
            results = await self._check_domain(target)
        else:
            results = {"error": "Target must be an email or domain", "breaches": []}

        cache.set("breach", target, results)
        return results

    # ── Per-email check (HIBP API — requires key) ──────────────────────────
    async def _check_email(self, email: str) -> dict:
        if not config.HIBP_API_KEY:
            self.log.warning("HIBP_API_KEY not set — skipping per-email check")
            return {
                "target":  email,
                "breaches": [],
                "pastes":   [],
                "note":    "Set HIBP_API_KEY in .env for per-email breach checks",
            }

        breaches, pastes = await asyncio.gather(
            self._hibp_breaches(email),
            self._hibp_pastes(email),
            return_exceptions=True,
        )
        if isinstance(breaches, Exception): breaches = []
        if isinstance(pastes,   Exception): pastes   = []

        result = {
            "target":          email,
            "total":       1,
            "breaches":        breaches,
            "pastes":          pastes,
            "breach_count":    len(breaches),
            "paste_count":     len(pastes),
            "is_pwned":        len(breaches) > 0 or len(pastes) > 0,
            "breach_names":    [b.get("Name", "") for b in breaches],
            "breach_dates":    [b.get("BreachDate", "") for b in breaches],
            "data_classes":    list({dc for b in breaches for dc in b.get("DataClasses", [])}),
        }

        self._log_breach_results(result)
        await self._persist_db(result)
        return result

    # ── Domain-level check (HIBP API — FREE, no key) ──────────────────────
    async def _check_domain(self, domain: str) -> dict:
        # HIBP v3 domain search (free, no key for breach list)
        all_breaches = await self._hibp_all_breaches()

        domain_breaches = [
            b for b in all_breaches
            if domain.lower() in b.get("Domain", "").lower()
        ]

        # Also check if the domain itself was breached
        site_breach = next(
            (b for b in all_breaches if domain.lower() in b.get("Domain", "").lower()),
            None,
        )

        result = {
            "target":          domain,
            "site_breached":   site_breach is not None,
            "site_breach_info": site_breach,
            "domain_breaches": domain_breaches,
            "breach_count":    len(domain_breaches),
            "total_pwn_count": sum(b.get("PwnCount", 0) for b in domain_breaches),
            "breach_names":    [b.get("Name", "") for b in domain_breaches],
        }

        self._log_breach_results(result)
        return result

    # ── HIBP API calls ─────────────────────────────────────────────────────
    async def _hibp_breaches(self, email: str) -> list[dict]:
        url     = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {
            **config.DEFAULT_HEADERS,
            "hibp-api-key": config.HIBP_API_KEY or "",
            "user-agent": "ProjectZ-OSINT-Framework",
        }
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
            elif _r["status"] == 404:
                return []   # Not pwned
            elif _r["status"] == 429:
                await rate_limiter.on_rate_limited("haveibeenpwned.com")
                return []
        except Exception as e:
            self.log.warning(f"HIBP breach error: {e}")
        return []

    async def _hibp_pastes(self, email: str) -> list[dict]:
        url     = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {
            **config.DEFAULT_HEADERS,
            "hibp-api-key": config.HIBP_API_KEY or "",
            "user-agent": "ProjectZ-OSINT-Framework",
        }
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
            elif _r["status"] == 404:
                return []
        except Exception as e:
            self.log.warning(f"HIBP pastes error: {e}")
        return []

    async def _hibp_all_breaches(self) -> list[dict]:
        """Get all known breaches — FREE, no key required."""
        url = "https://haveibeenpwned.com/api/v3/breaches"
        headers = {**config.DEFAULT_HEADERS, "user-agent": "ProjectZ-OSINT-Framework"}
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"HIBP all-breaches error: {e}")
        return []

    def _log_breach_results(self, r: dict) -> None:
        count = r.get("breach_count", 0)
        if count:
            self.log.warning(f"⚠ Found in {count} breach(es)!")
            for name in r.get("breach_names", [])[:5]:
                self.log.found("Breach", name)
            data_classes = r.get("data_classes", [])
            if data_classes:
                self.log.found("Leaked Data Types", ", ".join(data_classes[:6]))
        else:
            self.log.info("No breaches found in HIBP database")


    def _clean(self, t: str) -> str:
        """Strip scheme/www for domain targets; leave emails intact."""
        t = t.strip()
        if '@' in t:
            return t.lower()
        for p in ('https://', 'http://', 'www.'):
            if t.lower().startswith(p):
                t = t[len(p):]
        return t.split('/')[0].lower()

