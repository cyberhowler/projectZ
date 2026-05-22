"""
ProjectZ - Module 25: ZoomEye Alternative / Network Intelligence Aggregator
Aggregates open-port data from multiple FREE sources:
  - Shodan InternetDB (FREE JSON API)
  - ONYPHE community (FREE)
  - HackerTarget network tools (FREE)
  - Hurricane Electric BGP Toolkit (FREE)
Self-coded — zero paid API keys.
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


class ZoomEyeModule(BaseModule):
    MODULE_NAME = "zoomeye"
    DESCRIPTION = "Network intel aggregator — InternetDB, ONYPHE, HackerTarget, HE BGP"


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
        self.log.info(f"Network intel aggregation: {target}")

        cached = cache.get("zoomeye", target)
        if cached:
            return cached

        ip = target if self._is_ip(target) else await self._to_ip(target)
        if not ip:
            return {"target": target, "error": "Could not resolve IP"}

        idb, hackertarget, he_bgp, onyphe = await asyncio.gather(
            self._internetdb(ip),
            self._hackertarget(ip),
            self._he_bgp(ip),
            self._onyphe(ip),
            return_exceptions=True,
        )
        if isinstance(idb,          Exception): idb          = {}
        if isinstance(hackertarget, Exception): hackertarget = {}
        if isinstance(he_bgp,       Exception): he_bgp       = {}
        if isinstance(onyphe,       Exception): onyphe       = {}

        result = self._merge(target, ip, idb, hackertarget, he_bgp, onyphe)
        self._log_findings(result)
        cache.set("zoomeye", target, result)
        await self._persist_db(result)
        return result

    # ── Shodan InternetDB ──────────────────────────────────────────────────
    async def _internetdb(self, ip: str) -> dict:
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"InternetDB error: {e}")
        return {}

    # ── HackerTarget network tools ────────────────────────────────────────
    async def _hackertarget(self, ip: str) -> dict:
        results = {}
        endpoints = {
            "traceroute": f"https://api.hackertarget.com/mtr/?q={ip}",
            "port_scan":  f"https://api.hackertarget.com/nmap/?q={ip}",
        }
        for key, url in endpoints.items():
            try:
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    text = _r["text"]
                    if "error" not in text.lower() and "API" not in text:
                        results[key] = text[:500]
            except Exception as e:
                self.log.warning(f"HackerTarget {key} error: {e}")
            await asyncio.sleep(0.3)
        return results

    # ── Hurricane Electric BGP ────────────────────────────────────────────
    async def _he_bgp(self, ip: str) -> dict:
        url = f"https://bgp.he.net/ip/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                return self._parse_he_bgp(html)
        except Exception as e:
            self.log.warning(f"HE BGP error: {e}")
        return {}

    def _parse_he_bgp(self, html: str) -> dict:
        asn_m    = re.findall(r"AS(\d+)", html)
        prefix_m = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", html)
        org_m    = re.search(r"<b>([^<]{5,80})</b>", html)
        return {
            "asns":    list(set(f"AS{a}" for a in asn_m))[:5],
            "prefixes": list(set(prefix_m))[:10],
            "org":     org_m.group(1).strip() if org_m else "",
        }

    # ── ONYPHE community ──────────────────────────────────────────────────
    async def _onyphe(self, ip: str) -> dict:
        url = f"https://www.onyphe.io/api/v2/simple/inetnum/{ip}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"ONYPHE error: {e}")
        return {}

    # ── Merge ──────────────────────────────────────────────────────────────
    def _merge(self, target: str, ip: str, idb: dict, ht: dict,
               he: dict, onyphe: dict) -> dict:
        ports  = idb.get("ports", [])
        vulns  = idb.get("vulns", [])
        cpes   = idb.get("cpes", [])
        tags   = idb.get("tags", [])
        asns   = he.get("asns", [])
        prefixes = he.get("prefixes", [])

        # Try to parse ports from HackerTarget nmap output
        ht_ports = []
        nmap_out = ht.get("port_scan", "")
        for m in re.finditer(r"(\d+)/(\w+)\s+open\s+(\S+)", nmap_out):
            ht_ports.append({
                "port":    int(m.group(1)),
                "proto":   m.group(2),
                "service": m.group(3),
            })

        return {
            "target":            target,
            "total":             len(ports),
            "ip":                ip,
            "open_ports":        ports,
            "ht_port_details":   ht_ports,
            "vulnerabilities":   vulns,
            "cpes":              cpes,
            "tags":              tags,
            "asns":              asns,
            "bgp_prefixes":      prefixes,
            "org":               he.get("org", ""),
            "traceroute":        ht.get("traceroute", "")[:500],
            "has_vulns":         len(vulns) > 0,
            "sources":           ["shodan_internetdb", "hackertarget", "he_bgp", "onyphe"],
        }

    def _log_findings(self, r: dict) -> None:
        if r.get("open_ports"):
            self.log.found("Open Ports", str(len(r["open_ports"])))
        if r.get("has_vulns"):
            self.log.warning(f"⚠ {len(r['vulnerabilities'])} CVEs found!")
            for v in r["vulnerabilities"][:3]:
                self.log.found("CVE", v)
        if r.get("asns"):
            self.log.found("ASNs", ", ".join(r["asns"]))
        if r.get("cpes"):
            self.log.found("CPEs", ", ".join(r["cpes"][:3]))

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