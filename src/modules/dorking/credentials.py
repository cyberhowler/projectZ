"""
ProjectZ - Module 29: Credential / Secret Exposure
Dork for hardcoded secrets, leaked credentials, API keys,
tokens exposed on the web or in code repos.
Self-coded — Bing dorks + GitHub code search.
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

# ── Credential dork categories ────────────────────────────────────────────────
CRED_DORKS: dict[str, list[str]] = {
    "api_keys": [
        'site:{domain} "api_key" | "apikey" | "api-key" | "API_KEY"',
        'site:{domain} "access_token" | "auth_token" | "bearer_token"',
        'site:{domain} "aws_access_key_id" | "AKIA" | "aws_secret_access_key"',
    ],
    "passwords": [
        'site:{domain} "password" | "passwd" | "pwd" filetype:txt | filetype:log | filetype:env',
        'site:{domain} "db_password" | "database_password" | "mysql_password"',
        'site:{domain} intitle:"index of" "password" | "credentials"',
    ],
    "private_keys": [
        'site:{domain} "BEGIN RSA PRIVATE KEY" | "BEGIN OPENSSH PRIVATE KEY"',
        'site:{domain} "BEGIN EC PRIVATE KEY" | "BEGIN PGP PRIVATE KEY"',
        'site:{domain} ext:pem | ext:key | ext:ppk "PRIVATE"',
    ],
    "cloud_tokens": [
        'site:{domain} "SLACK_TOKEN" | "slack_webhook" | "xoxb-" | "xoxp-"',
        'site:{domain} "github_token" | "gh_token" | "GH_TOKEN"',
        'site:{domain} "STRIPE_SECRET" | "sk_live_" | "stripe_secret_key"',
        'site:{domain} "sendgrid_api_key" | "SG." | "SENDGRID"',
    ],
    "db_connection_strings": [
        'site:{domain} "mongodb://" | "postgresql://" | "mysql://" | "redis://"',
        'site:{domain} "Data Source=" "Initial Catalog=" | "Server=" "Database="',
        'site:{domain} "connectionString" | "connection_string" | "CONN_STR"',
    ],
    "oauth_secrets": [
        'site:{domain} "client_secret" | "oauth_secret" | "app_secret"',
        'site:{domain} "consumer_secret" | "consumer_key" | "CONSUMER_SECRET"',
        'site:{domain} "jwt_secret" | "JWT_SECRET" | "session_secret"',
    ],
}

# GitHub code search dorks (uses free search, no key needed for public repos)
GITHUB_DORKS: list[str] = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" "DB_PASSWORD"',
    '"{domain}" "BEGIN RSA PRIVATE KEY"',
]


class CredentialsModule(BaseModule):
    MODULE_NAME = "creds"
    DESCRIPTION = "Credential exposure dorks — API keys, passwords, tokens, private keys, DB strings"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Credential dork scan: {domain}")

        cached = cache.get("creds", domain)
        if cached:
            return cached

        # Concurrent: web dorks + GitHub code search
        web_findings, github_findings = await asyncio.gather(
            self._web_dorks(domain),
            self._github_search(domain),
            return_exceptions=True,
        )
        if isinstance(web_findings,    Exception): web_findings    = {}
        if isinstance(github_findings, Exception): github_findings = []

        total = sum(len(v) for v in web_findings.values()) + len(github_findings)

        _crit_cats = {"api_keys", "private_keys", "db_connection_strings"}
        critical_findings = [
            {"url": r["url"], "title": r.get("title",""), "label": cat}
            for cat, items in web_findings.items() if cat in _crit_cats
            for r in items
        ] + [{"url": r["url"], "title": r.get("title",""), "label": "github"} for r in github_findings]

        result = {
            "domain":            domain,
            "findings":          web_findings,
            "github_results":    github_findings,
            "total":             total,
            "categories":        {k: len(v) for k, v in web_findings.items()},
            "all_urls":          [r["url"] for findings in web_findings.values()
                                  for r in findings] + [r["url"] for r in github_findings],
            "has_api_keys":      len(web_findings.get("api_keys", [])) > 0,
            "has_private_keys":  len(web_findings.get("private_keys", [])) > 0,
            "has_db_strings":    len(web_findings.get("db_connection_strings", [])) > 0,
            "github_hits":       len(github_findings),
            "critical_findings": critical_findings,
            "high_findings":     [
                {"url": r["url"], "title": r.get("title",""), "label": cat}
                for cat, items in web_findings.items() if cat not in _crit_cats
                for r in items
            ],
        }

        for cat, items in web_findings.items():
            for item in items[:2]:
                self.log.warning(f"⚠ Credential leak [{cat}]: {item['url']}")

        for item in github_findings[:3]:
            self.log.warning(f"⚠ GitHub exposure: {item['url']}")

        cache.set("creds", domain, result)
        await self._persist_db(result)
        return result

    # ── Web dorks (Bing) ──────────────────────────────────────────────────
    async def _web_dorks(self, domain: str) -> dict[str, list[dict]]:
        sem      = asyncio.Semaphore(20)
        findings = {}

        async def _cat(category: str, dorks: list[str]):
            results = []
            for dork in dorks:
                async with sem:
                    query = dork.replace("{domain}", domain)
                    r     = await self._bing_search(query)
                    results.extend(r)
                    await asyncio.sleep(1.0)
            findings[category] = self._dedup(results)

        await asyncio.gather(
            *[_cat(cat, dorks) for cat, dorks in CRED_DORKS.items()],
            return_exceptions=True,
        )
        return findings

    async def _bing_search(self, query: str) -> list[dict]:
        url = f"https://www.bing.com/search?q={quote(query)}&count=15"
        results = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                html = _r["text"]
                results = self._parse_bing(html)
        except Exception as e:
            self.log.warning(f"Bing error: {e}")
        return results

    def _parse_bing(self, html: str) -> list[dict]:
        results = []
        for m in re.finditer(
            r'<h2><a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a></h2>',
            html, re.DOTALL,
        ):
            url   = m.group(1)
            title = re.sub(r"<[^>]+>", "", m.group(2)).strip()[:200]
            if "bing.com" not in url:
                results.append({"url": url, "title": title})
        return results[:10]

    # ── GitHub code search (FREE public search) ────────────────────────────
    async def _github_search(self, domain: str) -> list[dict]:
        results    = []
        headers    = {
            **config.DEFAULT_HEADERS,
            "Accept": "application/vnd.github.v3+json",
        }
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"

        for dork_tpl in GITHUB_DORKS[:4]:   # cap at 4 to avoid rate limits
            query = dork_tpl.replace("{domain}", domain)
            url   = f"https://api.github.com/search/code?q={quote(query)}&per_page=10"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                _r = await fetch(url, headers=headers, timeout=8)
                if _r["ok"]:
                    data = _r["json"]
                    for item in data.get("items", []):
                        results.append({
                            "url":  item.get("html_url", ""),
                            "repo": item.get("repository", {}).get("full_name", ""),
                            "file": item.get("name", ""),
                            "path": item.get("path", ""),
                        })
                elif _r["status"] == 429:
                    await rate_limiter.on_rate_limited("api.github.com")
            except Exception as e:
                self.log.warning(f"GitHub search error: {e}")
            await asyncio.sleep(2.0)   # GitHub search rate limit

        return self._dedup(results)

    def _dedup(self, items: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for item in items:
            key = item.get("url", "")
            if key and key not in seen:
                seen.add(key)
                clean.append(item)
        return clean


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
