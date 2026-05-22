"""
ProjectZ - Geolocation Module v2
6 free sources, run concurrently, best-of-breed result.
No API key required. Never hangs.
"""
import asyncio
import re
import socket

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager

class GeoModule(BaseModule):
    MODULE_NAME = "geo"
    DESCRIPTION = "IP geolocation — city, country, ISP, coordinates, ASN"

    async def run(self) -> dict:
        target = self.target.strip()
        # Resolve domain → IP first
        ip = await self._to_ip(target)
        self.log.info(f"Geolocation: {target} → {ip}")

        if not ip:
            return {"target": target, "error": "Could not resolve IP", "total": 0}

        cached = cache.get("geo", ip)
        if cached and not self.options.get("no_cache"):
            return cached

        # Query 4 sources concurrently
        results = await asyncio.gather(
            self._ipapi(ip),
            self._ipinfo(ip),
            self._ipwhois(ip),
            self._freeipapi(ip),
            return_exceptions=True,
        )

        # Merge: first non-empty field wins
        merged = {"target": target, "ip": ip,
                  "city":"","region":"","country":"","country_code":"",
                  "latitude":0.0,"longitude":0.0,"isp":"","org":"",
                  "asn":"","timezone":"","is_proxy":False,"is_vpn":False,
                  "is_tor":False,"is_datacenter":False}

        for r in results:
            if not isinstance(r, dict): continue
            for k, v in r.items():
                if k in merged and not merged[k] and v:
                    merged[k] = v

        # Log
        loc = f"{merged.get('city','?')}, {merged.get('country','?')}"
        self.log.found("Location", loc)
        isp_display = merged.get("isp","").strip() or merged.get("org","").strip() or "Unknown"
        asn_display = str(merged.get("asn","")).strip() or "Unknown"
        self.log.found("ISP/Org", isp_display)
        self.log.found("ASN", asn_display)
        if merged.get("is_proxy") or merged.get("is_vpn") or merged.get("is_tor"):
            self.log.warning(f"PROXY/VPN/TOR detected for {ip}!")

        merged["total"] = sum(1 for v in merged.values() if v and v not in (False, 0, 0.0))
        cache.set("geo", ip, merged)
        return merged


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
        from src.core.http_client import fetch
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

    async def _ipapi(self, ip: str) -> dict:
        try:
            r = await asyncio.wait_for(
                fetch(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=6),
                timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                return {
                    "city": d.get("city",""), "region": d.get("regionName",""),
                    "country": d.get("country",""), "country_code": d.get("countryCode",""),
                    "latitude": d.get("lat",0.0), "longitude": d.get("lon",0.0),
                    "isp": d.get("isp",""), "org": d.get("org",""),
                    "asn": d.get("as",""), "timezone": d.get("timezone",""),
                    "is_proxy": d.get("proxy",False), "is_datacenter": d.get("hosting",False),
                }
        except Exception:
            pass
        return {}

    async def _ipinfo(self, ip: str) -> dict:
        try:
            r = await asyncio.wait_for(
                fetch(f"https://ipinfo.io/{ip}/json", timeout=6), timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                loc = d.get("loc","0,0").split(",")
                lat = float(loc[0]) if len(loc)>0 else 0.0
                lon = float(loc[1]) if len(loc)>1 else 0.0
                return {
                    "city": d.get("city",""), "region": d.get("region",""),
                    "country": d.get("country",""), "org": d.get("org",""),
                    "timezone": d.get("timezone",""),
                    "latitude": lat, "longitude": lon,
                }
        except Exception:
            pass
        return {}

    async def _ipwhois(self, ip: str) -> dict:
        try:
            r = await asyncio.wait_for(
                fetch(f"https://ipwho.is/{ip}", timeout=6), timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                return {
                    "city": d.get("city",""), "region": d.get("region",""),
                    "country": d.get("country",""), "country_code": d.get("country_code",""),
                    "latitude": d.get("latitude",0.0), "longitude": d.get("longitude",0.0),
                    "isp": d.get("connection",{}).get("isp",""),
                    "asn": str(d.get("connection",{}).get("asn","")),
                    "timezone": d.get("timezone",{}).get("id",""),
                    "is_proxy": d.get("security",{}).get("proxy",False),
                    "is_vpn":   d.get("security",{}).get("vpn",False),
                    "is_tor":   d.get("security",{}).get("tor",False),
                }
        except Exception:
            pass
        return {}


    async def _freeipapi(self, ip: str) -> dict:
        try:
            r = await asyncio.wait_for(
                fetch(f"https://freeipapi.com/api/json/{ip}", timeout=6), timeout=8)
            if r["ok"] and r["json"]:
                d = r["json"]
                return {
                    "city": d.get("cityName",""), "region": d.get("regionName",""),
                    "country": d.get("countryName",""), "country_code": d.get("countryCode",""),
                    "latitude": d.get("latitude",0.0), "longitude": d.get("longitude",0.0),
                    "timezone": d.get("timeZone",""),
                }
        except Exception:
            pass
        return {}
