"""
ProjectZ - Module 28: Error Message / Info Disclosure Discovery
Dork for verbose error messages that leak stack traces,
DB info, server paths, framework versions, debug output.
Self-coded — Bing/Google dorks only.
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

# Dorks that find information-disclosing error pages
ERROR_DORKS: dict[str, list[str]] = {
    "stack_traces": [
        'site:{domain} "Fatal error" | "Warning:" | "Parse error" | "Notice:" "on line"',
        'site:{domain} "Exception in thread" | "Traceback (most recent call last)"',
        'site:{domain} "ORA-" | "MySQL Error" | "SQLSTATE" | "SQL syntax"',
        'site:{domain} "Microsoft OLE DB" | "ODBC SQL Server Driver" | "SQL Server"',
    ],
    "framework_errors": [
        'site:{domain} "Django" "Debug" "Request Method" | "Traceback"',
        'site:{domain} "Laravel" "Whoops" | "Exception" "Stack Trace"',
        'site:{domain} "Ruby on Rails" "ActionController" | "NoMethodError"',
        'site:{domain} "Spring" "NullPointerException" | "ApplicationContext"',
    ],
    "path_disclosure": [
        'site:{domain} "Warning: include(" | "Warning: require(" | "failed to open stream"',
        'site:{domain} "root_path" | "DOCUMENT_ROOT" | "SERVER_NAME" "/var/www" | "/home/"',
        'site:{domain} "Directory listing" | "Index of /" "Parent Directory"',
    ],
    "server_info": [
        'site:{domain} "Apache/2" | "nginx/1" | "IIS/7" inurl:error | inurl:404',
        'site:{domain} "PHP/7" | "PHP/8" inurl:phpinfo | intitle:"phpinfo()"',
        'site:{domain} "Tomcat" "Apache Tomcat" "HTTP Status 404" | "HTTP Status 500"',
    ],
    "debug_pages": [
        'site:{domain} inurl:debug | inurl:trace | inurl:test | inurl:dev',
        'site:{domain} intitle:"Debug" | intitle:"Test Page" | intitle:"Under Construction"',
        'site:{domain} "DEBUG = True" | "APP_DEBUG=true" | "FLASK_DEBUG"',
    ],
    "credentials_leak": [
        'site:{domain} "password" | "passwd" | "pwd" filetype:log | filetype:txt',
        'site:{domain} "API Key" | "api_key" | "apikey" filetype:txt | filetype:log',
        'site:{domain} "BEGIN RSA PRIVATE KEY" | "BEGIN OPENSSH PRIVATE KEY"',
    ],
}


class ErrorMsgModule(BaseModule):
    MODULE_NAME = "errors"
    DESCRIPTION = "Error message / info disclosure dorks — stack traces, DB errors, path leaks"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Error/info disclosure dorks: {domain}")

        cached = cache.get("errors", domain)
        if cached:
            return cached

        all_findings: dict[str, list[dict]] = {}
        total = 0

        # Run all dork categories concurrently (with rate limiting)
        sem = asyncio.Semaphore(20)  # max 3 searches at once to avoid blocks

        async def _search_category(category: str, dorks: list[str]):
            findings = []
            for dork in dorks:
                async with sem:
                    results = await self._search(dork.replace("{domain}", domain))
                    findings.extend(results)
                    await asyncio.sleep(1.2)
            return category, self._dedup(findings)

        tasks = [_search_category(cat, dorks) for cat, dorks in ERROR_DORKS.items()]
        raw   = await asyncio.gather(*tasks, return_exceptions=True)

        for item in raw:
            if isinstance(item, tuple):
                cat, findings = item
                all_findings[cat] = findings
                total += len(findings)
                if findings:
                    self.log.found(f"Info Leak [{cat}]", str(len(findings)))

        _high_cats = {"stack_traces", "debug_pages", "path_disclosure"}

        result = {
            "domain":      domain,
            "findings":    all_findings,
            "total":       total,
            "categories":  {k: len(v) for k, v in all_findings.items()},
            "all_urls":    [r["url"] for cat_findings in all_findings.values()
                            for r in cat_findings],
            "has_db_errors":     len(all_findings.get("stack_traces", [])) > 0,
            "has_path_disclosure":len(all_findings.get("path_disclosure", [])) > 0,
            "has_debug_pages":   len(all_findings.get("debug_pages", [])) > 0,
            "high_findings":     [{"url": r["url"], "title": r.get("title",""), "label": cat}
                                  for cat, items in all_findings.items() if cat in _high_cats
                                  for r in items],
            "critical_findings": [],
        }

        for cat, items in all_findings.items():
            for item in items[:2]:
                self.log.found(f"Leak [{cat}]", item["url"])

        cache.set("errors", domain, result)
        await self._persist_db(result)
        return result

    async def _search(self, query: str) -> list[dict]:
        results = []
        for engine_url in [
            f"https://www.bing.com/search?q={quote(query)}&count=15",
        ]:
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                _r = await fetch(engine_url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    html = _r["text"]
                    results.extend(self._parse_bing(html))
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
