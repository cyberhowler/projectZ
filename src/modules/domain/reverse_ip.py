"""
ProjectZ - Module 08: Reverse IP / Virtual Host Enumeration
Find all domains sharing the same IP (shared hosting detection).
Self-coded using HackerTarget free API + DNS brute-validation.
"""

from __future__ import annotations

import asyncio
import re
import socket

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class ReverseIPModule(BaseModule):
    MODULE_NAME = "reverseip"
    DESCRIPTION = "Reverse IP / vhost enumeration — all domains on same IP"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Reverse IP lookup: {domain}")

        cached = cache.get("reverseip", domain)
        if cached:
            return cached

        # Resolve IP
        ip = await self._resolve(domain)
        if not ip:
            return {"domain": domain, "error": "Could not resolve IP", "domains_on_ip": []}

        self.log.info(f"Resolved {domain} → {ip}")

        # Query multiple sources concurrently
        ht_domains, viewdns_domains = await asyncio.gather(
            self._hackertarget(ip),
            self._viewdns(ip),
            return_exceptions=True,
        )

        if isinstance(ht_domains, Exception):      ht_domains      = []
        if isinstance(viewdns_domains, Exception): viewdns_domains = []

        all_domains = list(dict.fromkeys(ht_domains + viewdns_domains))

        result = {
            "domain":         domain,
            "ip":             ip,
            "domains_on_ip":  all_domains,
            "total":          len(all_domains),
            "shared_hosting": len(all_domains) > 1,
            "sources": {
                "hackertarget": len(ht_domains),
                "viewdns":      len(viewdns_domains),
            },
        }

        self.log.found("IP", ip)
        self.log.found("Domains on IP", str(len(all_domains)))
        for d in all_domains[:5]:
            self.log.found("Co-hosted Domain", d)
        if len(all_domains) > 5:
            self.log.info(f"... and {len(all_domains)-5} more")

        cache.set("reverseip", domain, result)
        await self._persist_db(result)
        return result

    # ── HackerTarget free API ──────────────────────────────────────────────
    async def _hackertarget(self, ip: str) -> list[str]:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                text = _r["text"]
                if "error" in text.lower() or "API count" in text:
                    return []
                domains = [
                    line.strip() for line in text.splitlines()
                    if line.strip() and self._valid_domain(line.strip())
                ]
                return domains
        except Exception as e:
            self.log.warning(f"HackerTarget error: {e}")
        return []

    # ── ViewDNS.info free API ──────────────────────────────────────────────
    async def _viewdns(self, ip: str) -> list[str]:
        url = f"https://viewdns.info/reverseip/?host={ip}&apikey=free"
        # ViewDNS returns HTML — parse it
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                text = _r["text"]
                # Extract domains from HTML table
                domains = re.findall(
                    r"<td>([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>",
                    text
                )
                return [d for d in domains if self._valid_domain(d)]
        except Exception as e:
            self.log.warning(f"ViewDNS error: {e}")
        return []

    # ── Helpers ───────────────────────────────────────────────────────────
    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""

    def _valid_domain(self, s: str) -> bool:
        return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", s))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
