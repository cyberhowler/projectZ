"""
ProjectZ - Module 23: Censys Alternative
Internet scanning intelligence via:
  - Censys public search (no key for HTML scrape)
  - FOFA search engine (free public queries)
  - Shodan InternetDB (completely FREE JSON API — no key)
Self-coded — no paid API keys required.
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


class CensysAltModule(BaseModule):
    MODULE_NAME = "censys"
    DESCRIPTION = "Internet scan intelligence — Shodan InternetDB (free) + Censys + FOFA"


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
        self.log.info(f"Censys-alt scan: {target}")

        cached = cache.get("censys", target)
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._to_ip(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        # Run all three concurrently
        internetdb, censys_html, fofa = await asyncio.gather(
            self._shodan_internetdb(ip),
            self._censys_public(ip),
            self._fofa_search(ip),
            return_exceptions=True,
        )
        if isinstance(internetdb,  Exception): internetdb  = {}
        if isinstance(censys_html, Exception): censys_html = {}
        if isinstance(fofa,        Exception): fofa        = {}

        result = self._merge(target, ip, internetdb, censys_html, fofa)
        self._log_findings(result)
        cache.set("censys", target, result)
        await self._persist_db(result)
        return result

    # ── Shodan InternetDB — 100% FREE JSON API ─────────────────────────────
    async def _shodan_internetdb(self, ip: str) -> dict:
        """
        https://internetdb.shodan.io/{ip}
        Returns: ports, cpes, hostnames, tags, vulns — completely free.
        """
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"InternetDB error: {e}")
        return {}

    # ── Censys.io public page ─────────────────────────────────────────────
    async def _censys_public(self, ip: str) -> dict:
        url = f"https://search.censys.io/hosts/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                return self._parse_censys_html(html)
        except Exception as e:
            self.log.warning(f"Censys public error: {e}")
        return {}

    def _parse_censys_html(self, html: str) -> dict:
        ports    = re.findall(r'"port":\s*(\d+)', html)
        services = re.findall(r'"service_name":\s*"([^"]+)"', html)
        labels   = re.findall(r'"label":\s*"([^"]+)"', html)
        return {
            "ports":    [int(p) for p in ports],
            "services": list(set(services))[:10],
            "labels":   list(set(labels))[:10],
            "source":   "censys_public",
        }

    # ── FOFA public search ─────────────────────────────────────────────────
    async def _fofa_search(self, ip: str) -> dict:
        query = f'ip="{ip}"'
        url   = f"https://en.fofa.info/result?qbase64={self._b64(query)}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                return self._parse_fofa_html(html)
        except Exception as e:
            self.log.warning(f"FOFA error: {e}")
        return {}

    def _parse_fofa_html(self, html: str) -> dict:
        ports    = re.findall(r':(\d{2,5})\b', html)
        titles   = re.findall(r'class="title"[^>]*>([^<]{3,80})<', html)
        services = re.findall(r'"protocol":\s*"([^"]+)"', html)
        return {
            "ports":    list(set(int(p) for p in ports if int(p) < 65536))[:20],
            "titles":   list(set(t.strip() for t in titles))[:10],
            "services": list(set(services))[:10],
            "source":   "fofa",
        }

    def _b64(self, s: str) -> str:
        import base64
        return base64.b64encode(s.encode()).decode()

    # ── Merge ──────────────────────────────────────────────────────────────
    def _merge(self, target: str, ip: str, idb: dict, censys: dict, fofa: dict) -> dict:
        # InternetDB is most reliable — use as primary
        ports_idb    = idb.get("ports", [])
        ports_censys = censys.get("ports", [])
        ports_fofa   = fofa.get("ports", [])

        all_ports = sorted(set(ports_idb + ports_censys + ports_fofa))
        vulns     = idb.get("vulns", [])
        cpes      = idb.get("cpes", [])
        tags      = idb.get("tags", [])
        hostnames = idb.get("hostnames", [])

        return {
            "target":        target,
            "total":         len(all_ports),
            "ip":            ip,
            "open_ports":    all_ports,
            "port_count":    len(all_ports),
            "cpes":          cpes,
            "vulnerabilities": vulns,
            "tags":          tags,
            "hostnames":     hostnames,
            "services":      censys.get("services", []) + fofa.get("services", []),
            "has_vulns":     len(vulns) > 0,
            "sources":       ["shodan_internetdb", "censys_public", "fofa"],
        }

    def _log_findings(self, r: dict) -> None:
        self.log.found("Ports", str(r.get("port_count", 0)))
        if r.get("has_vulns"):
            self.log.warning(f"⚠ {len(r['vulnerabilities'])} CVEs detected!")
            for cve in r["vulnerabilities"][:5]:
                self.log.found("CVE", cve)
        if r.get("cpes"):
            self.log.found("CPEs", ", ".join(r["cpes"][:4]))
        if r.get("hostnames"):
            self.log.found("Hostnames", ", ".join(r["hostnames"][:4]))

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