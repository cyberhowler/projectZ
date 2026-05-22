"""
ProjectZ - Module 27: Admin Panel Discovery
Brute-force common admin panel paths + dork for login pages.
Uses wordlist from data/wordlists/admin-panels.txt.
Self-coded — pure HTTP probing.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from typing import Optional
from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager, wordlists
from src.core.config import config

# Extra high-value paths not always in wordlist
EXTRA_PATHS = [
    "/admin", "/administrator", "/admin/login", "/admin/index.php",
    "/wp-admin", "/wp-login.php", "/wp-admin/admin-ajax.php",
    "/login", "/signin", "/auth", "/auth/login",
    "/cpanel", "/plesk", "/phpmyadmin", "/pma",
    "/webmail", "/roundcube", "/squirrelmail",
    "/jenkins", "/grafana", "/kibana", "/portainer",
    "/console", "/manager/html", "/host-manager/html",   # Tomcat
    "/.env", "/.git/config", "/.htpasswd", "/.htaccess",
    "/config.php", "/config.yml", "/config.json",
    "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui",
    "/actuator", "/actuator/health", "/actuator/env",    # Spring Boot
    "/debug", "/debug/pprof", "/debug/vars",
    "/_cats", "/_nodes", "/_cluster/health",             # Elasticsearch
    "/solr/admin", "/solr/#/",
    "/redis/redis.conf", "/etc/passwd",
]

# Indicators that confirm a real admin panel (not just 200 OK)
ADMIN_INDICATORS = [
    "login", "password", "username", "sign in", "admin",
    "dashboard", "panel", "console", "management", "authenticate",
    "jwt", "oauth", "session", "csrf",
]


class AdminPanelModule(BaseModule):
    MODULE_NAME = "admin"
    DESCRIPTION = "Admin panel discovery — wordlist probe + login page detection + dorks"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Admin panel discovery: {domain}")

        cached = cache.get("admin_panels", domain)
        if cached:
            return cached

        # Merge wordlist + extra paths, deduplicate
        wl_paths = wordlists.admin_panels()
        all_paths = list(dict.fromkeys(EXTRA_PATHS + wl_paths))

        self.log.info(f"Probing {len(all_paths)} paths on {domain}")

        found, interesting = await asyncio.gather(
            self._probe_all(domain, all_paths),
            self._dork_search(domain),
            return_exceptions=True,
        )
        if isinstance(found,       Exception): found       = []
        if isinstance(interesting, Exception): interesting = []

        # Merge and deduplicate by path
        all_found = self._merge(found, interesting)

        result = {
            "domain":            domain,
            "panels_found":      all_found,
            "total":             len(all_found),
            "paths_probed":      len(all_paths),
            "login_pages":       [p for p in all_found if p.get("is_login")],
            "exposed_files":     [p for p in all_found if p.get("is_sensitive")],
            "sources": {
                "probe":  len(found),
                "dorks":  len(interesting),
            },
            # Engine _persist() reads these keys
            "high_findings":     [{"url": p["url"], "title": p.get("title","Admin panel found")}
                                  for p in all_found if p.get("is_login")],
            "critical_findings": [{"url": p["url"], "title": p.get("title","Sensitive file exposed")}
                                  for p in all_found if p.get("is_sensitive")],
        }

        for panel in all_found[:8]:
            tag = "[LOGIN]" if panel.get("is_login") else "[SENSITIVE]" if panel.get("is_sensitive") else "[FOUND]"
            self.log.found(f"Admin {tag}", panel["url"])

        cache.set("admin_panels", domain, result)
        await self._persist_db(result)
        return result

    # ── HTTP path probing ──────────────────────────────────────────────────
    async def _probe_all(self, domain: str, paths: list[str]) -> list[dict]:
        sem     = asyncio.Semaphore(25)
        found   = []

        async def _probe(path: str):
            for scheme in ("https", "http"):
                url    = f"{scheme}://{domain}{path}"
                result = await self._check_url(url, sem)
                if result:
                    found.append(result)
                    break  # https worked — don't try http too

        await asyncio.gather(*[_probe(p) for p in paths], return_exceptions=True)
        return found

    async def _check_url(self, url: str, sem: asyncio.Semaphore) -> Optional[dict]:
        async with sem:
            try:
                timeout = aiohttp.ClientTimeout(total=6)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with rate_limiter.throttle(url.split("/")[2]):
                        _r = await fetch(
                            url,
                            headers=config.DEFAULT_HEADERS,
                            allow_redirects=True, timeout=8)
                        if _r["status"] in (200, 401, 403):
                                body   = ""
                                if _r["ok"]:
                                    body = _r["text"]
                                    body = body[:5000].lower()

                                title_m = re.search(
                                    r"<title[^>]*>(.*?)</title>",
                                    body, re.IGNORECASE | re.DOTALL,
                                )
                                title = re.sub(r"\s+", " ",
                                               title_m.group(1)).strip()[:100] if title_m else ""

                                is_login     = any(ind in body for ind in ADMIN_INDICATORS)
                                is_sensitive = any(p in url for p in
                                                   ["/.env", "/.git", "/.htpasswd",
                                                    "/config", "/passwd"])
                                is_api       = any(p in url for p in
                                                   ["/api", "/swagger", "/actuator",
                                                    "/_cat", "/_nodes"])

                                return {
                                    "url":          url,
                                    "status":       _r["status"],
                                    "title":        title,
                                    "is_login":     is_login,
                                    "is_sensitive": is_sensitive,
                                    "is_api":       is_api,
                                    "content_type": _r["headers"].get("Content-Type", "")[:80],
                                }
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
        return None

    # ── Dork for login/admin pages ─────────────────────────────────────────
    async def _dork_search(self, domain: str) -> list[dict]:
        dorks = [
            f'site:{domain} inurl:admin | inurl:login | inurl:signin | inurl:dashboard',
            f'site:{domain} intitle:"login" | intitle:"admin panel" | intitle:"control panel"',
            f'site:{domain} inurl:wp-admin | inurl:administrator | inurl:phpmyadmin',
        ]
        results = []
        for dork in dorks:
            url = f"https://www.bing.com/search?q={quote(dork)}&count=10"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    html    = _r["text"]
                    for m in re.finditer(
                        r'<a[^>]+href="(https?://[^"]+)"', html
                    ):
                        u = m.group(1)
                        if domain in u and "bing.com" not in u:
                            results.append({
                                "url":          u,
                                "status":       0,
                                "title":        "",
                                "is_login":     True,
                                "is_sensitive": False,
                                "is_api":       False,
                                "source":       "dork",
                            })
            except Exception as e:
                self.log.warning(f"Dork error: {e}")
            await asyncio.sleep(1.0)
        return results

    # ── Merge + dedup by URL ───────────────────────────────────────────────
    def _merge(self, a: list[dict], b: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for item in a + b:
            if item["url"] not in seen:
                seen.add(item["url"])
                clean.append(item)
        return sorted(clean, key=lambda x: (not x.get("is_sensitive"),
                                             not x.get("is_login"),
                                             x["url"]))


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
