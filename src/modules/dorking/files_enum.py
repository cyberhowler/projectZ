"""
ProjectZ - Module 26: Sensitive File Enumeration
Google/Bing dorks to discover exposed files:
  config, backup, DB dumps, .env, keys, spreadsheets, PDFs, source code.
Self-coded — no paid APIs.
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

# ── Dork categories ───────────────────────────────────────────────────────────
FILE_DORKS: dict[str, list[str]] = {
    "config_files": [
        'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini',
        'site:{domain} ext:env | ext:env.bak | ext:env.old',
        'site:{domain} "DB_PASSWORD" | "DB_USER" | "APP_KEY" | "SECRET_KEY"',
    ],
    "backup_files": [
        'site:{domain} ext:bak | ext:backup | ext:old | ext:orig | ext:save | ext:swp',
        'site:{domain} ext:sql | ext:sql.gz | ext:sql.bz2 | ext:dump',
        'site:{domain} ext:zip | ext:tar.gz | ext:tgz | ext:7z filetype:zip',
    ],
    "sensitive_docs": [
        'site:{domain} ext:xlsx | ext:xls | ext:csv filetype:xlsx',
        'site:{domain} ext:pdf "confidential" | "internal use" | "restricted"',
        'site:{domain} ext:doc | ext:docx "password" | "credentials"',
    ],
    "source_code": [
        'site:{domain} ext:php | ext:asp | ext:aspx | ext:jsp "password" | "passwd" | "pwd"',
        'site:{domain} ext:py | ext:rb | ext:go "api_key" | "secret" | "token"',
        'site:{domain} ext:js "api_key" | "apiKey" | "secret" | "password"',
    ],
    "logs_debug": [
        'site:{domain} ext:log | ext:log.1 | ext:log.gz',
        'site:{domain} "index of" "parent directory"',
        'site:{domain} inurl:debug | inurl:trace | inurl:phpinfo',
    ],
    "credentials": [
        'site:{domain} intext:"username" intext:"password" ext:txt | ext:log',
        'site:{domain} "private key" | "BEGIN RSA" | "BEGIN OPENSSH"',
        'site:{domain} ext:pem | ext:key | ext:p12 | ext:pfx',
    ],
}


class FilesEnumModule(BaseModule):
    MODULE_NAME = "files"
    DESCRIPTION = "Sensitive file discovery — Google/Bing dorks for configs, backups, credentials"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"File enumeration dorks: {domain}")

        cached = cache.get("files_enum", domain)
        if cached:
            return cached

        all_findings: dict[str, list[dict]] = {}
        total = 0

        for category, dorks in FILE_DORKS.items():
            findings = []
            for dork in dorks:
                query    = dork.replace("{domain}", domain)
                results  = await self._search(query)
                findings.extend(results)
                await asyncio.sleep(1.5)  # polite delay between dorks

            # Deduplicate by URL
            seen  = set()
            clean = []
            for r in findings:
                if r["url"] not in seen:
                    seen.add(r["url"])
                    clean.append(r)

            all_findings[category] = clean
            total += len(clean)
            if clean:
                self.log.found(f"Files [{category}]", str(len(clean)))

        _critical_cats = {"backup_files", "credentials"}
        _high_cats     = {"config_files", "source_code", "logs_debug"}

        critical_findings = [
            {"url": r["url"], "title": r.get("title",""), "label": cat}
            for cat, items in all_findings.items() if cat in _critical_cats
            for r in items
        ]
        high_findings = [
            {"url": r["url"], "title": r.get("title",""), "label": cat}
            for cat, items in all_findings.items() if cat in _high_cats
            for r in items
        ]

        result = {
            "domain":            domain,
            "findings":          all_findings,
            "total":             total,
            "categories":        {k: len(v) for k, v in all_findings.items()},
            "all_urls":          [r["url"] for findings in all_findings.values() for r in findings],
            "critical_findings": critical_findings,
            "high_findings":     high_findings,
        }

        for category, items in all_findings.items():
            for item in items[:3]:
                self.log.found(f"Exposed [{category}]", item["url"])

        cache.set("files_enum", domain, result)
        await self._persist_db(result)
        return result

    # ── Bing search (less aggressive blocking than Google) ─────────────────
    async def _search(self, query: str) -> list[dict]:
        url = f"https://www.bing.com/search?q={quote(query)}&count=20"
        results = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html    = _r["text"]
                results = self._parse_results(html)
        except Exception as e:
            self.log.warning(f"Search error: {e}")
        return results

    def _parse_results(self, html: str) -> list[dict]:
        results = []
        # Bing result links pattern
        pattern = re.compile(
            r'<a[^>]+href="(https?://[^"]+)"[^>]*><h2>(.*?)</h2>',
            re.DOTALL | re.IGNORECASE,
        )
        for m in pattern.finditer(html):
            url   = m.group(1)
            title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            # Skip Bing internal URLs
            if "bing.com" not in url and "microsoft.com" not in url:
                results.append({"url": url, "title": title[:200]})
        return results[:15]


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
