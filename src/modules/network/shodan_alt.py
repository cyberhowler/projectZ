"""
ProjectZ - Module 22: Shodan Alternative (Censys/Fofa/Zoomeye-style)
Internet-connected device discovery using FREE public search engines:
  - Shodan HTML scrape (no key needed for basic data)
  - Censys free search  
  - Criminal IP (free tier)
Self-coded — zero paid APIs needed.
"""

import asyncio
import re
import socket
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class ShodanAltModule(BaseModule):
    MODULE_NAME = "shodan"
    DESCRIPTION = "Internet device discovery — Shodan public data + Criminal IP free"


    async def _to_ip(self, target: str) -> str:
        """Resolve domain to IP. Tries OS DNS first, then DoH HTTP fallback."""
        import re as _re
        if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
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
        from src.core.http_client import fetch
        for doh in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
            try:
                import asyncio as _a2
                r = await _a2.wait_for(
                    fetch(doh, params={"name": target, "type": "A"},
                          headers={"Accept": "application/dns-json"}, timeout=5),
                    timeout=6)
                if r.get("ok") and r.get("json"):
                    for ans in r["json"].get("Answer", []):
                        if ans.get("type") == 1:
                            return ans.get("data", "")
            except Exception:
                continue
        return ""


    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"Internet device discovery: {target}")

        cached = cache.get("shodan", target)
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._to_ip(target)

        # Concurrent queries
        shodan_data, criminalip_data = await asyncio.gather(
            self._shodan_public(ip or target),
            self._criminalip(ip or target),
            return_exceptions=True,
        )
        if isinstance(shodan_data,    Exception): shodan_data    = {}
        if isinstance(criminalip_data, Exception): criminalip_data = {}

        result = self._merge(target, ip or target, shodan_data, criminalip_data)
        self._log_findings(result)
        cache.set("shodan", target, result)
        await self._persist_db(result)
        return result

    # ── Shodan public host page (no API key) ──────────────────────────────
    async def _shodan_public(self, ip: str) -> dict:
        url = f"https://www.shodan.io/host/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                return self._parse_shodan_html(html, ip)
        except Exception as e:
            self.log.warning(f"Shodan public error: {e}")
        return {}

    def _parse_shodan_html(self, html: str, ip: str) -> dict:
        # Extract service banners from Shodan's public page
        ports_found = re.findall(r'<td class="col-md-2">(\d+)/(\w+)</td>', html)
        services    = re.findall(r'<h6 class="title">(.*?)</h6>', html)
        org_m       = re.search(r'Organization\s*</dt>\s*<dd[^>]*>(.*?)</dd>', html, re.DOTALL)
        isp_m       = re.search(r'ISP\s*</dt>\s*<dd[^>]*>(.*?)</dd>', html, re.DOTALL)
        country_m   = re.search(r'Country\s*</dt>.*?title="([^"]+)"', html, re.DOTALL)
        os_m        = re.search(r'Operating System\s*</dt>\s*<dd[^>]*>(.*?)</dd>', html, re.DOTALL)

        def _clean_tag(s):
            return re.sub(r"<[^>]+>", "", s or "").strip()

        ports = [{"port": int(p), "proto": proto} for p, proto in ports_found]
        return {
            "ports":    ports,
            "services": [_clean_tag(s) for s in services[:10]],
            "org":      _clean_tag(org_m.group(1)) if org_m else "",
            "isp":      _clean_tag(isp_m.group(1)) if isp_m else "",
            "country":  _clean_tag(country_m.group(1)) if country_m else "",
            "os":       _clean_tag(os_m.group(1)) if os_m else "",
            "source":   "shodan_public",
        }

    # ── Criminal IP free tier (no key for basic) ──────────────────────────
    async def _criminalip(self, ip: str) -> dict:
        url = f"https://www.criminalip.io/asset/report/summary?ip={ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                return data
        except Exception as e:
            self.log.warning(f"CriminalIP error: {e}")
        return {}

    # ── Merge results ──────────────────────────────────────────────────────
    def _merge(self, target: str, ip: str, shodan: dict, criminalip: dict) -> dict:
        ports = shodan.get("ports", [])
        cip   = criminalip.get("data", {}) if isinstance(criminalip.get("data"), dict) else {}

        return {
            "target":       target,
            "total":        len(ports),
            "ip":           ip,
            "open_ports":   ports,
            "port_numbers": [p["port"] for p in ports],
            "port_count":   len(ports),
            "services":     shodan.get("services", []),
            "org":          shodan.get("org", ""),
            "isp":          shodan.get("isp", ""),
            "country":      shodan.get("country", ""),
            "os":           shodan.get("os", ""),
            "criminalip_score": cip.get("score", ""),
            "sources":      ["shodan_public", "criminalip"],
        }

    def _log_findings(self, r: dict) -> None:
        self.log.found("Ports Seen", str(r.get("port_count", 0)))
        if r.get("org"):     self.log.found("Org", r["org"])
        if r.get("os"):      self.log.found("OS", r["os"])
        if r.get("country"): self.log.found("Country", r["country"])
        for p in r.get("open_ports", [])[:8]:
            self.log.found(f"Port {p['port']}", p.get("proto", "tcp"))

    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""

    def _is_ip(self, s: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]