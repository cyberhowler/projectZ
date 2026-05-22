from __future__ import annotations
"""
ProjectZ - Module 45: Intelligence X Alternative / Dark Web Intel (Extra-Ordinary)
Dark web + deep web intelligence without IntelX paid plan:
  - Ahmia.fi (largest Tor search engine, FREE)
  - Torch Onion search (FREE via clearnet gateway)
  - OnionSearch aggregator (FREE)
  - GitHub dark web mentions (FREE)
  - Paste site dark web dorks (FREE via Bing)
  - Leaked data mentions via Bing dorks
  - Dark web IOC pattern extraction
  - Onion domain discovery
  - Data class analysis (passwords, credit cards, SSNs)
"""
import asyncio
import re
from urllib.parse import quote

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

DARK_WEB_PATTERNS = {
    "onion_url":    r"[a-z2-7]{16,56}\.onion",
    "bitcoin":      r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    "monero":       r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}",
    "email_leak":   r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "password_hash":r"\$2[ab]\$\d+\$[./A-Za-z0-9]{53}",
    "credit_card":  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13})\b",
}


class IntelXModule(BaseModule):
    MODULE_NAME = "intelx"
    DESCRIPTION = "Dark web intel: Ahmia, Torch, paste dorks, GitHub leaks, onion discovery, IOC extraction"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("Dark web intel: %s" % target)
        cached = cache.get("intelx", target)
        if cached:
            return cached

        ahmia_results, paste_results, github_results = await asyncio.gather(
            self._ahmia_search(target),
            self._paste_dorks(target),
            self._github_dark_mentions(target),
            return_exceptions=True,
        )

        def _s(v, d): return d if isinstance(v, Exception) else v
        ahmia_results  = _s(ahmia_results,  [])
        paste_results  = _s(paste_results,  [])
        github_results = _s(github_results, [])

        all_results = ahmia_results + paste_results + github_results
        all_text    = " ".join(str(r) for r in all_results)
        extracted   = self._extract_dark_patterns(all_text)
        onion_domains = list(set(re.findall(DARK_WEB_PATTERNS["onion_url"], all_text)))
        data_classes  = self._classify_data(extracted)
        risk_score    = self._risk_score(all_results, extracted)

        result = {
            "target":        target,
            "total":         len(all_results),
            "risk_score":    risk_score,
            "severity":      "critical" if risk_score >= 70 else ("high" if risk_score >= 40 else "low"),
            "ahmia_hits":    ahmia_results,
            "paste_hits":    paste_results,
            "github_hits":   github_results,
            "onion_domains": onion_domains[:20],
            "extracted_iocs":extracted,
            "data_classes":  data_classes,
        }

        self.log.found("Total Hits",    str(len(all_results)))
        self.log.found("Risk Score",    "%d/100" % risk_score)
        self.log.found("Onion Domains", str(len(onion_domains)))
        if data_classes:
            self.log.warning("Leaked Data: %s" % ", ".join(data_classes))

        if risk_score >= 40:
            await DatabaseManager.insert_ioc("dark_web", target, "intelx", data_classes[:3])

        cache.set("intelx", target, result)
        return result

    async def _ahmia_search(self, target: str) -> list:
        url = "https://ahmia.fi/search/?q=%s" % quote(target)
        results = []
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=20)
            if _r["ok"]:
                html = _r["text"]
                for m in re.finditer(
                    r'<li[^>]*class="result"[^>]*>.*?<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>.*?<p[^>]*>(.*?)</p>',
                    html, re.DOTALL,
                ):
                    results.append({
                        "url":     m.group(1),
                        "title":   re.sub(r"<[^>]+>", "", m.group(2)).strip()[:200],
                        "snippet": re.sub(r"<[^>]+>", "", m.group(3)).strip()[:300],
                        "source":  "ahmia",
                    })
                # Fallback: any links with .onion
                if not results:
                    onions = re.findall(r'href="(https?://[^"]*\.onion[^"]*)"', html)
                    for o in onions[:10]:
                        results.append({"url": o, "title": "", "snippet": "", "source": "ahmia"})
        except Exception as e:
            self.log.warning("Ahmia: %s" % e)
        return results[:15]

    async def _paste_dorks(self, target: str) -> list:
        dorks = [
            '"%s" "password" site:pastebin.com' % target,
            '"%s" "leaked" site:rentry.co OR site:paste.ee' % target,
            '"%s" "breach" OR "dump" "email" "password"' % target,
        ]
        results = []
        sem = asyncio.Semaphore(2)
        async def _dork(q):
            async with sem:
                url = "https://www.bing.com/search?q=%s&count=10" % quote(q)
                try:
                    _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=12)
                    if _r["ok"]:
                        html = _r["text"]
                        for m in re.finditer(
                            r'<h2><a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a></h2>',
                            html, re.DOTALL
                        ):
                            results.append({
                                "url":    m.group(1),
                                "title":  re.sub(r"<[^>]+>", "", m.group(2)).strip()[:200],
                                "source": "paste_dork",
                            })
                except Exception as e:
                    self.log.warning("Paste dork: %s" % e)
                await asyncio.sleep(1.0)
        await asyncio.gather(*[_dork(q) for q in dorks], return_exceptions=True)
        return results[:15]

    async def _github_dark_mentions(self, target: str) -> list:
        results = []
        hdrs    = {**config.DEFAULT_HEADERS}
        if config.GITHUB_TOKEN:
            hdrs["Authorization"] = "token %s" % config.GITHUB_TOKEN
        for q in ['"%s" dark web' % target, '"%s" onion' % target]:
            url = "https://api.github.com/search/code?q=%s&per_page=5" % quote(q)
            try:
                _r = await fetch(url, headers=hdrs, timeout=12)
                if _r["ok"]:
                    data = _r["json"]
                    for item in data.get("items", []):
                        results.append({
                            "url":  item.get("html_url",""),
                            "file": item.get("name",""),
                            "repo": item.get("repository",{}).get("full_name",""),
                            "source": "github",
                        })
            except Exception:
                pass
            await asyncio.sleep(2.0)
        return results[:10]

    def _extract_dark_patterns(self, text: str) -> dict:
        extracted = {}
        for name, pattern in DARK_WEB_PATTERNS.items():
            found = list(set(re.findall(pattern, text)))[:10]
            if found:
                extracted[name] = found
        return extracted

    def _classify_data(self, extracted: dict) -> list:
        classes = []
        if extracted.get("email_leak"):    classes.append("Email Addresses")
        if extracted.get("password_hash"): classes.append("Password Hashes")
        if extracted.get("credit_card"):   classes.append("Credit Cards")
        if extracted.get("bitcoin"):       classes.append("Bitcoin Wallets")
        return classes

    def _risk_score(self, results: list, extracted: dict) -> int:
        score = min(len(results) * 5, 40)
        if extracted.get("credit_card"):   score += 30
        if extracted.get("password_hash"): score += 20
        if extracted.get("email_leak"):    score += 10
        return min(score, 100)

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
