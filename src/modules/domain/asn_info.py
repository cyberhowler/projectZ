"""
ProjectZ - Module 06: ASN / BGP Information
Autonomous System Number, BGP prefix, organisation, country.
Self-coded using ipinfo.io (free tier) + bgpview.io (free API).
"""

import asyncio
import re
import socket

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class ASNModule(BaseModule):
    MODULE_NAME = "asn"
    DESCRIPTION = "ASN/BGP mapping — AS number, prefix, organisation, country"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"ASN lookup: {target}")

        cached = cache.get("asn", target)
        if cached:
            return cached

        # Resolve domain → IP if needed
        ip = target if self._is_ip(target) else await self._to_ip(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        # Query both sources concurrently
        ipinfo, bgpview = await asyncio.gather(
            self._ipinfo(ip),
            self._bgpview(ip),
            return_exceptions=True,
        )

        if isinstance(ipinfo, Exception):  ipinfo  = {}
        if isinstance(bgpview, Exception): bgpview = {}

        result = self._merge(target, ip, ipinfo, bgpview)
        cache.set("asn", target, result)
        await self._persist_db(result)
        return result

    # ── ipinfo.io (free, no key needed for basic) ──────────────────────────
    async def _ipinfo(self, ip: str) -> dict:
        url = f"https://ipinfo.io/{ip}/json"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"ipinfo.io error: {e}")
        return {}

    # ── bgpview.io (free, no key) ──────────────────────────────────────────
    async def _bgpview(self, ip: str) -> dict:
        url = f"https://api.bgpview.io/ip/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                return data.get("data", {})
        except Exception as e:
            self.log.warning(f"bgpview.io error: {e}")
        return {}

    # ── Merge both sources ─────────────────────────────────────────────────
    def _merge(self, target: str, ip: str, ipinfo: dict, bgpview: dict) -> dict:
        # Extract ASN from bgpview prefixes
        asn_num  = ""
        asn_name = ""
        prefixes = []
        peers    = []

        bgp_prefixes = bgpview.get("prefixes", [])
        if bgp_prefixes:
            p    = bgp_prefixes[0]
            asn  = p.get("asn", {})
            asn_num  = f"AS{asn.get('asn', '')}"
            asn_name = asn.get("description", "")
            prefixes = [x.get("prefix", "") for x in bgp_prefixes[:10]]

        # Fallback from ipinfo
        if not asn_num and ipinfo.get("org"):
            parts = ipinfo["org"].split(" ", 1)
            asn_num  = parts[0] if parts else ""
            asn_name = parts[1] if len(parts) > 1 else ""

        result = {
            "target":       target,
            "total":       1,
            "ip":           ip,
            "asn":          asn_num,
            "asn_name":     asn_name,
            "country":      ipinfo.get("country", ""),
            "region":       ipinfo.get("region", ""),
            "city":         ipinfo.get("city", ""),
            "postal":       ipinfo.get("postal", ""),
            "timezone":     ipinfo.get("timezone", ""),
            "org":          ipinfo.get("org", asn_name),
            "hostname":     ipinfo.get("hostname", ""),
            "bgp_prefixes": prefixes,
            "total_prefixes": len(bgp_prefixes),
        }

        for k, v in [("ASN", asn_num), ("Org", asn_name), ("Country", result["country"]),
                     ("BGP Prefixes", str(len(prefixes)))]:
            if v:
                self.log.found(k, v)

        return result


    async def _to_ip(self, target: str) -> str:
        """Resolve domain to IP. Tries OS DNS first, then DoH fallback."""
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        # Method 1: OS socket DNS
        import socket as _s, asyncio as _a
        loop = _a.get_event_loop()
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=1) as ex:
                results = await _a.wait_for(
                    loop.run_in_executor(ex, _s.getaddrinfo, target, None, _s.AF_INET),
                    timeout=3.0)
                if results:
                    return results[0][4][0]
        except Exception:
            pass
        # Method 2: DoH (works when OS DNS is blocked/unavailable)
        for doh in ("https://cloudflare-dns.com/dns-query",
                    "https://dns.google/resolve"):
            try:
                r = await _a.wait_for(
                    fetch(doh, params={"name": target, "type": "A"},
                          headers={"Accept": "application/dns-json"}, timeout=5),
                    timeout=6)
                if r.get("ok") and r.get("json"):
                    answers = r["json"].get("Answer", [])
                    for ans in answers:
                        if ans.get("type") == 1:   # A record
                            return ans.get("data", "")
            except Exception:
                continue
        return ""

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
