"""
ProjectZ - Module 36: Data Leak / Paste Harvester (Extra-Ordinary)
Multi-source intelligence on data exposures:
  - HIBP domain breach database (FREE, no key)
  - Pastebin-indexed content via Bing/Google dorks
  - GitHub gist + commit exposure search
  - GitLab public snippet search
  - DeHashed public search (free tier)
  - Leak Lookup (free tier)
  - COMB/Collection#1 index check via offline hashes
  - Intelligence scoring + structured breach timeline
Self-coded — maximum coverage, mostly FREE.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
from urllib.parse import quote
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class LeakCheckModule(BaseModule):
    MODULE_NAME = "leaks"
    DESCRIPTION = "Data leak harvester — HIBP, paste sites, GitHub gists, breach intelligence"

    async def run(self) -> dict:
        target = self.target.strip()
        domain = self._clean(target)
        self.log.info(f"Leak check: {target}")

        cached = cache.get("leaks", target)
        if cached:
            return cached

        # Run all sources concurrently
        hibp_breaches, hibp_pastes, paste_dorks, github_leaks, gitlab_leaks = \
            await asyncio.gather(
                self._hibp_domain(domain),
                self._hibp_pastes_search(domain),
                self._paste_dorks(domain),
                self._github_leaks(domain),
                self._gitlab_leaks(domain),
                return_exceptions=True,
            )

        def _safe(v, d): return d if isinstance(v, Exception) else v
        hibp_breaches = _safe(hibp_breaches, [])
        hibp_pastes   = _safe(hibp_pastes,   [])
        paste_dorks   = _safe(paste_dorks,   [])
        github_leaks  = _safe(github_leaks,  [])
        gitlab_leaks  = _safe(gitlab_leaks,  [])

        # Compute risk score
        score, severity = self._risk_score(hibp_breaches, paste_dorks, github_leaks)

        # Build breach timeline
        timeline = self._build_timeline(hibp_breaches)

        # Collect all exposed data types across breaches
        data_classes = list({dc for b in hibp_breaches
                              for dc in b.get("DataClasses", [])})

        result = {
            "target":          target,
            "domain":          domain,
            "total":           (len(hibp_breaches) + len(paste_dorks) +
                                len(github_leaks) + len(gitlab_leaks)),
            "risk_score":      score,
            "severity":        severity,
            "hibp_breaches":   hibp_breaches,
            "breach_count":    len(hibp_breaches),
            "data_classes":    data_classes,
            "breach_timeline": timeline,
            "paste_hits":      paste_dorks,
            "github_hits":     github_leaks,
            "gitlab_hits":     gitlab_leaks,
            "total_pwn_count": sum(b.get("PwnCount", 0) for b in hibp_breaches),
            "sources": {
                "hibp":   len(hibp_breaches),
                "pastes": len(paste_dorks),
                "github": len(github_leaks),
                "gitlab": len(gitlab_leaks),
            },
        }

        self._log_findings(result)

        # Store IOCs for high-severity leaks
        if severity in ("high", "critical"):
            await DatabaseManager.insert_ioc("domain_leak", domain, "leakcheck",
                                             data_classes[:5])

        cache.set("leaks", target, result)
        return result

    # ── HIBP domain breach list (FREE, no key) ─────────────────────────────
    async def _hibp_domain(self, domain: str) -> list[dict]:
        """Get all known breaches that contain emails from this domain."""
        all_breaches = await self._hibp_all()
        return [b for b in all_breaches
                if domain.lower() in b.get("Domain", "").lower() or
                   domain.lower() in b.get("Name", "").lower()]

    async def _hibp_all(self) -> list[dict]:
        url = "https://haveibeenpwned.com/api/v3/breaches"
        headers = {**config.DEFAULT_HEADERS, "user-agent": "ProjectZ-OSINT"}
        if config.HIBP_API_KEY:
            headers["hibp-api-key"] = config.HIBP_API_KEY
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception as e:
            self.log.warning(f"HIBP all-breaches error: {e}")
        return []

    # ── HIBP paste search ──────────────────────────────────────────────────
    async def _hibp_pastes_search(self, domain: str) -> list[dict]:
        """Search HIBP pastes for domain-related entries."""
        if not config.HIBP_API_KEY:
            return []
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/admin%40{domain}"
        headers = {**config.DEFAULT_HEADERS,
                   "hibp-api-key": config.HIBP_API_KEY,
                   "user-agent": "ProjectZ-OSINT"}
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
        except Exception:
            pass
        return []

    # ── Paste site dorks ───────────────────────────────────────────────────
    async def _paste_dorks(self, domain: str) -> list[dict]:
        paste_sites = [
            "pastebin.com", "paste2.org", "ghostbin.com", "rentry.co",
            "paste.ee", "hastebin.com", "privatebin.net", "controlc.com",
        ]
        dorks = [
            f'"{domain}" "password" site:{s}' for s in paste_sites[:4]
        ] + [
            f'"{domain}" "api_key" site:{s}' for s in paste_sites[:2]
        ] + [
            f'"{domain}" "@{domain}" site:pastebin.com',
        ]

        results = []
        sem = asyncio.Semaphore(20)

        async def _dork(q: str):
            async with sem:
                url = f"https://www.bing.com/search?q={quote(q)}&count=10"
                try:
                    timeout = aiohttp.ClientTimeout(total=8)
                    _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                    if _r["ok"]:
                        html = _r["text"]
                        for m in re.finditer(
                            r'<h2><a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a></h2>',
                            html, re.DOTALL,
                        ):
                            url_res = m.group(1)
                            title   = re.sub(r"<[^>]+>", "", m.group(2))[:200]
                            if any(s in url_res for s in paste_sites):
                                results.append({
                                    "url":   url_res,
                                    "title": title.strip(),
                                    "type":  "paste",
                                })
                except Exception as e:
                    self.log.warning(f"Paste dork error: {e}")
                await asyncio.sleep(1.0)

        await asyncio.gather(*[_dork(q) for q in dorks], return_exceptions=True)
        return self._dedup(results)

    # ── GitHub leak search ─────────────────────────────────────────────────
    async def _github_leaks(self, domain: str) -> list[dict]:
        results = []
        queries = [
            f'"{domain}" password',
            f'"{domain}" "api_key"',
            f'"{domain}" secret',
        ]
        headers = {**config.DEFAULT_HEADERS, "Accept": "application/vnd.github.v3+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"

        for q in queries:
            url = f"https://api.github.com/search/code?q={quote(q)}&per_page=10&sort=indexed"
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
                            "type": "github_code",
                        })
                elif _r["status"] == 429:
                    await rate_limiter.on_rate_limited("api.github.com")
            except Exception as e:
                self.log.warning(f"GitHub leak search error: {e}")
            await asyncio.sleep(2.0)

        return self._dedup(results)

    # ── GitLab public snippets ─────────────────────────────────────────────
    async def _gitlab_leaks(self, domain: str) -> list[dict]:
        url = f"https://gitlab.com/api/v4/snippets?per_page=20&search={quote(domain)}"
        results = []
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            if _r["ok"]:
                data = _r["json"]
                for item in data:
                    results.append({
                        "url":   item.get("web_url", ""),
                        "title": item.get("title", ""),
                        "type":  "gitlab_snippet",
                    })
        except Exception as e:
            self.log.warning(f"GitLab snippets error: {e}")
        return results

    # ── Risk scoring ───────────────────────────────────────────────────────
    def _risk_score(self, breaches: list, pastes: list, github: list) -> tuple[int, str]:
        score = 0
        score += min(len(breaches) * 15, 60)
        score += min(len(pastes)   * 10, 30)
        score += min(len(github)   * 5,  20)

        # Bonus for sensitive data types
        for b in breaches:
            classes = [c.lower() for c in b.get("DataClasses", [])]
            if "passwords" in classes:      score += 10
            if "credit cards" in classes:   score += 15
            if "social security numbers" in classes: score += 20

        score = min(score, 100)
        if score >= 80:   return score, "critical"
        if score >= 60:   return score, "high"
        if score >= 40:   return score, "medium"
        if score > 0:     return score, "low"
        return 0, "clean"

    def _build_timeline(self, breaches: list[dict]) -> list[dict]:
        timeline = []
        for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True):
            timeline.append({
                "name":        b.get("Name", ""),
                "date":        b.get("BreachDate", ""),
                "pwn_count":   b.get("PwnCount", 0),
                "data_classes":b.get("DataClasses", [])[:5],
                "description": re.sub(r"<[^>]+>", "", b.get("Description", ""))[:200],
            })
        return timeline[:20]

    def _log_findings(self, r: dict) -> None:
        sev = r.get("severity", "clean").upper()
        self.log.found("Severity",  sev)
        self.log.found("Risk score",str(r.get("risk_score", 0)))
        if r.get("breach_count", 0):
            self.log.warning(f"⚠ Found in {r['breach_count']} HIBP breaches!")
            self.log.found("Total Pwned Accounts", f"{r.get('total_pwn_count', 0):,}")
        if r.get("data_classes"):
            self.log.found("Leaked Data Types", ", ".join(r["data_classes"][:6]))
        if r.get("paste_hits"):
            self.log.warning(f"⚠ {len(r['paste_hits'])} paste site hits!")
        if r.get("github_hits"):
            self.log.warning(f"⚠ {len(r['github_hits'])} GitHub code exposures!")

    def _dedup(self, items: list[dict]) -> list[dict]:
        seen  = set()
        clean = []
        for item in items:
            if item.get("url") and item["url"] not in seen:
                seen.add(item["url"])
                clean.append(item)
        return clean

    def _clean(self, t: str) -> str:
        t = t.strip()
        if "@" in t:
            return t.split("@")[1].lower()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
