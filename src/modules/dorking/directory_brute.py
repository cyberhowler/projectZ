from __future__ import annotations
"""
ProjectZ - Module 31: Directory Brute-Force
Async HTTP directory/file brute-force using built-in wordlist.
Detects 200, 301, 302, 401, 403 responses.
Extracts page titles, content types, response sizes.
Self-coded — pure asyncio, no external tools required.
"""

import asyncio
import re
from pathlib import Path

from typing import Optional
from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager, wordlists
from src.core.config import config

# Interesting status codes to record
INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}

# High-value paths always checked regardless of wordlist
PRIORITY_PATHS = [
    ".env", ".git/config", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "phpinfo.php", "info.php", "test.php", "debug.php", "config.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "config.yml", "config.yaml", "config.json", "config.ini", "config.env",
    "database.yml", "settings.py", "local.py", "production.py",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "package.json", "composer.json", "Gemfile",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "admin/", "dashboard/", "api/", "swagger/", "swagger-ui/",
    "actuator/", "actuator/env", "actuator/health", "actuator/beans",
    "_cats/", "_nodes/", "_cluster/health",
    "server-status", "server-info",
    "trace", "TRACE",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

# Words indicating sensitive/interesting content
SENSITIVE_INDICATORS = [
    "password", "secret", "key", "token", "credential", "private",
    "internal", "debug", "error", "exception", "traceback", "stack",
    "database", "config", "env", "backup",
]


class DirBruteModule(BaseModule):
    MODULE_NAME = "dirbust"
    DESCRIPTION = "Directory brute-force — async HTTP, wordlist + priority paths, title extraction"

    async def run(self) -> dict:
        domain  = self._clean(self.target)
        limit   = self.options.get("wordlist_limit", 300)
        self.log.info(f"Directory brute-force: {domain} (wordlist={limit})")

        cached = cache.get("dirbust", domain)
        if cached:
            return cached

        # Build path list: priority first, then wordlist
        wl_paths = wordlists.admin_panels()   # reuse admin-panels list
        all_paths = list(dict.fromkeys(
            PRIORITY_PATHS + wl_paths[:limit]
        ))

        self.log.info(f"Testing {len(all_paths)} paths")

        # Try HTTPS first, fall back to HTTP
        base_url = await self._detect_scheme(domain)

        sem     = asyncio.Semaphore(30)
        results = await asyncio.gather(
            *[self._probe(base_url, path, sem) for path in all_paths],
            return_exceptions=True,
        )

        found = [r for r in results if isinstance(r, dict)]

        # Categorise
        exposed     = [r for r in found if r["status"] == 200]
        redirects   = [r for r in found if r["status"] in (301, 302, 307)]
        auth_req    = [r for r in found if r["status"] in (401, 403)]
        sensitive   = [r for r in found if r.get("is_sensitive")]

        result = {
            "domain":         domain,
            "base_url":       base_url,
            "paths_tested":   len(all_paths),
            "found":          found,
            "total":          len(found),
            "total_found":    len(found),
            "exposed":        exposed,
            "redirects":      redirects,
            "auth_required":  auth_req,
            "sensitive_files":sensitive,
            "summary": {
                "200_ok":    len(exposed),
                "301_302":   len(redirects),
                "401_403":   len(auth_req),
                "sensitive": len(sensitive),
            },
            "high_findings":     [{"url": r["url"], "title": r.get("title","Exposed path")} for r in exposed],
            "critical_findings": [{"url": r["url"], "title": r.get("title","Sensitive file")} for r in sensitive],
        }

        for r in sensitive[:5]:
            self.log.warning(f"⚠ Sensitive: {r['url']}")
        for r in exposed[:10]:
            title = f" [{r['title']}]" if r.get("title") else ""
            self.log.found(f"200 OK{title}", r["url"])
        for r in auth_req[:5]:
            self.log.found(f"401/403", r["url"])

        cache.set("dirbust", domain, result)
        await self._persist_db(result)
        return result

    # ── Detect working scheme ──────────────────────────────────────────────
    async def _detect_scheme(self, domain: str) -> str:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            try:
                _r = await fetch(url, timeout=8)
                if _r["status"] < 500:
                    return f"{scheme}://{domain}"
            except Exception:
                pass
        return f"https://{domain}"

    # ── Single path probe ──────────────────────────────────────────────────
    async def _probe(self, base_url: str, path: str,
                     sem: asyncio.Semaphore) -> Optional[dict]:
        # Normalise path
        if not path.startswith("/"):
            path = f"/{path}"
        url  = f"{base_url}{path}"
        host = base_url.split("/")[2]

        async with sem:
            try:
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, allow_redirects=False, timeout=8)
                if _r["status"] not in INTERESTING:
                    return None

                body    = ""
                title   = ""
                size    = 0

                if _r["status"] in (200, 201, 401, 403, 500):
                    try:
                        body = await asyncio.wait_for(
                            resp.text(errors="ignore"), timeout=3
                        )
                        size = len(body)
                        body = body[:3000]
                        title_m = re.search(
                            r"<title[^>]*>(.*?)</title>",
                            body, re.IGNORECASE | re.DOTALL,
                        )
                        if title_m:
                            title = re.sub(
                                r"\s+", " ", title_m.group(1)
                            ).strip()[:100]
                    except asyncio.TimeoutError:
                        pass

                is_sensitive = (
                    _r["status"] == 200 and
                    any(kw in path.lower() or kw in body.lower()
                        for kw in SENSITIVE_INDICATORS)
                )
                redirect_to  = ""
                if _r["status"] in (301, 302, 307):
                    redirect_to = _r["headers"].get("Location", "")[:200]

                return {
                    "url":          url,
                    "path":         path,
                    "status":       _r["status"],
                    "title":        title,
                    "size":         size,
                    "content_type": _r["headers"].get(
                        "Content-Type", "")[:80],
                    "is_sensitive": is_sensitive,
                    "redirect_to":  redirect_to,
                }
            except asyncio.TimeoutError:
                return None
            except Exception:
                return None


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
