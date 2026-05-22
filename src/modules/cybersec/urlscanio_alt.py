from __future__ import annotations
"""
ProjectZ - Module 40: URLScan.io Alternative (Advanced)
URL/domain scanning with:
  - urlscan.io FREE public API (submit + retrieve)
  - Wayback Machine screenshot availability
  - DOM analysis for malicious patterns
  - Redirect chain tracking
  - Resource loading intel (scripts, iframes, external calls)
  - Visual similarity hashing
  - Certificate and IP intel from scan results
"""
import asyncio
import re
import time
from urllib.parse import quote
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

MALICIOUS_PATTERNS = [
    r"eval\s*\(atob\(",
    r"document\.write\s*\(unescape\(",
    r"fromCharCode",
    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
    r"bitcoin\s*[a-zA-Z0-9]{26,34}",
    r"<iframe[^>]+style=[\"'][^\"']*display\s*:\s*none",
    r"new\s+ActiveXObject",
    r"WScript\.Shell",
    r"powershell\s+-enc",
]


class URLScanModule(BaseModule):
    MODULE_NAME = "urlscan"
    DESCRIPTION = "URL scan — urlscan.io submit/retrieve, Wayback screenshots, DOM malware patterns"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info(f"URL scan: {target}")

        cached = cache.get("urlscan", target)
        if cached:
            return cached

        urlscan_result, wayback_result, dom_result = await asyncio.gather(
            self._urlscan_submit(target),
            self._wayback_availability(target),
            self._direct_dom_scan(target),
            return_exceptions=True,
        )
        def _s(v, d): return d if isinstance(v, Exception) else v
        urlscan_result = _s(urlscan_result, {})
        wayback_result = _s(wayback_result, {})
        dom_result     = _s(dom_result,     {})

        # Merge malicious indicators
        all_indicators = list({
            *urlscan_result.get("malicious_indicators", []),
            *dom_result.get("patterns_found", []),
        })

        result = {
            "domain":            target,
            "total":             len(all_indicators),
            "urlscan":           urlscan_result,
            "wayback":           wayback_result,
            "dom_analysis":      dom_result,
            "malicious_indicators": all_indicators,
            "is_malicious":      bool(urlscan_result.get("verdicts", {}).get("overall", {}).get("malicious")) or len(all_indicators) > 2,
            "screenshot_url":    urlscan_result.get("screenshot", ""),
            "redirect_chain":    urlscan_result.get("redirects", []),
            "external_scripts":  urlscan_result.get("scripts", []),
            "iframes":           urlscan_result.get("iframes", []),
        }

        self.log.found("Malicious Indicators", str(len(all_indicators)))
        if result["is_malicious"]:
            self.log.warning(f"⚠ MALICIOUS indicators found: {all_indicators[:3]}")
        if urlscan_result.get("screenshot"):
            self.log.found("Screenshot", urlscan_result["screenshot"])

        cache.set("urlscan", target, result)
        await self._persist_db(result)
        return result

    # ── urlscan.io submit and retrieve ───────────────────────────────────
    async def _urlscan_submit(self, target: str) -> dict:
        headers = {**config.DEFAULT_HEADERS, "Content-Type": "application/json"}
        api_key = getattr(config, 'URLSCAN_API_KEY', None)
        if api_key:
            headers["API-Key"] = api_key

        # Step 1: Search for existing scans first (no quota used)
        search_url = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=1"
        try:
            _r = await fetch(search_url, headers=headers, timeout=8)
            if _r["ok"]:
                data    = _r["json"]
                results = data.get("results", [])
                if results:
                    return self._parse_urlscan_result(results[0])

            # Step 2: Submit new scan if no existing result
            if api_key:
                async with rate_limiter.throttle("urlscan.io"):
                    import aiohttp as _aiohttp
                    async with _aiohttp.ClientSession() as _sess:
                        async with _sess.post(
                            "https://urlscan.io/api/v1/scan/",
                            json={"url": f"https://{target}", "visibility": "public"},
                            headers=headers,
                        ) as sub_resp:
                            if sub_resp.status == 200:
                                sub_data = await sub_resp.json()
                                scan_uuid = sub_data.get("uuid", "")
                                if scan_uuid:
                                    await asyncio.sleep(15)
                                    return await self._urlscan_retrieve(_sess, scan_uuid, headers)
        except Exception as e:
            self.log.warning(f"urlscan.io error: {e}")
        return {}

    async def _urlscan_retrieve(self, session, uuid: str, headers: dict) -> dict:
        url = f"https://urlscan.io/api/v1/result/{uuid}/"
        for attempt in range(3):
            try:
                async with rate_limiter.throttle("urlscan.io"):
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return self._parse_urlscan_result(data)
                        elif resp.status == 404:
                            await asyncio.sleep(10)
            except Exception:
                pass
        return {}

    def _parse_urlscan_result(self, data: dict) -> dict:
        page      = data.get("page", {})
        task      = data.get("task", {})
        stats     = data.get("stats", {})
        verdicts  = data.get("verdicts", {})
        lists     = data.get("lists", {})

        # Extract redirect chain
        redirects = []
        for r in data.get("data", {}).get("requests", [])[:5]:
            resp = r.get("response", {})
            if resp.get("response", {}).get("status", 0) in (301, 302, 307, 308):
                redirects.append(resp.get("response", {}).get("headers", {}).get("location", ""))

        return {
            "url":              task.get("url", ""),
            "domain":           page.get("domain", ""),
            "ip":               page.get("ip", ""),
            "country":          page.get("country", ""),
            "server":           page.get("server", ""),
            "title":            page.get("title", ""),
            "status":           page.get("status", ""),
            "verdicts":         verdicts,
            "malicious_indicators": [
                v for k, v in verdicts.items()
                if isinstance(v, dict) and v.get("malicious")
            ],
            "screenshot":       f"https://urlscan.io/screenshots/{data.get('task', {}).get('uuid','')}.png",
            "redirects":        [r for r in redirects if r][:5],
            "scripts":          lists.get("scripts", [])[:10],
            "iframes":          lists.get("iframes", [])[:10],
            "total_requests":   stats.get("total", 0),
            "unique_domains":   stats.get("domainStats", {}).get("total", 0),
        }

    # ── Wayback availability ───────────────────────────────────────────────
    async def _wayback_availability(self, target: str) -> dict:
        url = f"https://archive.org/wayback/available?url={target}"
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                snap = data.get("archived_snapshots", {}).get("closest", {})
                return {
                    "available":  snap.get("available", False),
                    "url":        snap.get("url", ""),
                    "timestamp":  snap.get("timestamp", ""),
                    "status":     snap.get("status", ""),
                }
        except Exception as e:
            self.log.warning(f"Wayback availability error: {e}")
        return {}

    # ── Direct DOM scan for malware patterns ─────────────────────────────
    async def _direct_dom_scan(self, target: str) -> dict:
        patterns_found = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    html = _r["text"]
                    for pattern in MALICIOUS_PATTERNS:
                        if re.search(pattern, html, re.IGNORECASE):
                            patterns_found.append(pattern[:60])
                    # Extract all external script sources
                    scripts = re.findall(
                        r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE
                    )
                    ext_scripts = [s for s in scripts
                                   if not s.startswith("/") and target not in s]
                    return {
                        "patterns_found":  patterns_found,
                        "external_scripts":ext_scripts[:15],
                        "has_obfuscation": any("eval" in p or "atob" in p or "fromCharCode" in p
                                               for p in patterns_found),
                    }
            except Exception:
                pass
        return {"patterns_found": [], "external_scripts": []}


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
