"""
ProjectZ - Module 30: Vulnerability Dorks
Dork for known-vulnerable endpoints, CVE-specific patterns,
outdated software versions, and misconfigured services.
Self-coded — Bing dorks + ExploitDB search.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# ── Vulnerability dork categories ─────────────────────────────────────────────
VULN_DORKS: dict[str, list[str]] = {
    "injection": [
        'site:{domain} inurl:"id=" | inurl:"cat=" | inurl:"page=" | inurl:"search="',
        'site:{domain} inurl:".php?id=" | inurl:".asp?id=" | inurl:".aspx?id="',
        'site:{domain} inurl:"union select" | inurl:"1=1" | inurl:"or 1=1"',
    ],
    "exposed_services": [
        'site:{domain} inurl:":8080" | inurl:":8443" | inurl:":3000" | inurl:":5000"',
        'site:{domain} intitle:"Grafana" | intitle:"Kibana" | intitle:"Prometheus"',
        'site:{domain} intitle:"phpMyAdmin" | intitle:"Adminer" | intitle:"pgAdmin"',
        'site:{domain} intitle:"Jenkins" | intitle:"GitLab" | intitle:"Portainer"',
    ],
    "default_creds": [
        'site:{domain} intitle:"Welcome to nginx" | intitle:"Apache2 Default Page"',
        'site:{domain} intitle:"IIS Windows Server" | intitle:"Welcome to IIS"',
        'site:{domain} intitle:"RouterOS" | intitle:"Synology" | intitle:"QNAP"',
    ],
    "file_inclusion": [
        'site:{domain} inurl:"?file=" | inurl:"?path=" | inurl:"?include="',
        'site:{domain} inurl:"?template=" | inurl:"?lang=" | inurl:"?dir="',
    ],
    "cms_vulns": [
        'site:{domain} inurl:wp-content/plugins | inurl:wp-includes',
        'site:{domain} inurl:"/modules/" inurl:".php" | inurl:"/components/"',
        'site:{domain} inurl:"joomla" | inurl:"drupal" intitle:"login" | intitle:"admin"',
    ],
    "open_redirects": [
        'site:{domain} inurl:"redirect=" | inurl:"return=" | inurl:"next=" | inurl:"url="',
        'site:{domain} inurl:"goto=" | inurl:"target=" | inurl:"rurl=" | inurl:"dest="',
    ],
    "cors_misconfig": [
        'site:{domain} inurl:"/api/" | inurl:"/v1/" | inurl:"/v2/"',
        'site:{domain} "Access-Control-Allow-Origin: *"',
    ],
    "ssrf_candidates": [
        'site:{domain} inurl:"?url=" | inurl:"?proxy=" | inurl:"?fetch="',
        'site:{domain} inurl:"?webhook=" | inurl:"?callback=" | inurl:"?host="',
    ],
}


class VulnsDorksModule(BaseModule):
    MODULE_NAME = "vulns"
    DESCRIPTION = "Vulnerability dorks — injections, exposed services, CMS vulns, SSRF candidates"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Vulnerability dorks: {domain}")

        cached = cache.get("vulns", domain)
        if cached:
            return cached

        sem      = asyncio.Semaphore(20)
        findings = {}

        async def _cat(category: str, dorks: list[str]):
            results = []
            for dork in dorks:
                async with sem:
                    query = dork.replace("{domain}", domain)
                    r     = await self._search(query)
                    results.extend(r)
                    await asyncio.sleep(1.1)
            findings[category] = self._dedup(results)

        await asyncio.gather(
            *[_cat(cat, dorks) for cat, dorks in VULN_DORKS.items()],
            return_exceptions=True,
        )

        # Risk scoring
        high_risk   = []
        medium_risk = []
        for cat, items in findings.items():
            for item in items:
                if cat in ("injection", "file_inclusion", "default_creds", "exposed_services"):
                    high_risk.append(item)
                else:
                    medium_risk.append(item)

        total = sum(len(v) for v in findings.values())

        result = {
            "domain":       domain,
            "findings":     findings,
            "total":        total,
            "high_risk":    high_risk[:20],
            "medium_risk":  medium_risk[:20],
            "categories":   {k: len(v) for k, v in findings.items()},
            "all_urls":     [r["url"] for cat_finds in findings.values() for r in cat_finds],
            "risk_summary": {
                "high":   len(high_risk),
                "medium": len(medium_risk),
                "total":  total,
            },
            # Engine _persist() reads these keys for DB storage
            "high_findings":     [{"url": r["url"], "title": r.get("title","")} for r in high_risk[:20]],
            "critical_findings": [],   # Vuln dorks = high at most; critical reserved for confirmed RCE
        }

        for cat, items in findings.items():
            for item in items[:2]:
                level = "HIGH" if cat in ("injection", "file_inclusion") else "MED"
                self.log.warning(f"⚠ Vuln [{level}][{cat}]: {item['url']}")

        cache.set("vulns", domain, result)
        await self._persist_db(result)
        return result

    async def _search(self, query: str) -> list[dict]:
        url = f"https://www.bing.com/search?q={quote(query)}&count=15"
        results = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                results = self._parse_bing(html)
        except Exception as e:
            self.log.warning(f"Search error: {e}")
        return results

    def _parse_bing(self, html: str) -> list[dict]:
        results = []
        for m in re.finditer(
            r'<h2><a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a></h2>',
            html, re.DOTALL,
        ):
            url   = m.group(1)
            title = re.sub(r"<[^>]+>", "", m.group(2)).strip()[:200]
            if "bing.com" not in url and "microsoft.com" not in url:
                results.append({"url": url, "title": title})
        return results[:10]

    def _dedup(self, items: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for item in items:
            if item["url"] not in seen:
                seen.add(item["url"])
                clean.append(item)
        return clean


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
