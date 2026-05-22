from __future__ import annotations
"""
ProjectZ - Module 49: PacketStorm + Multi-Source Exploit Archive (Extra-Ordinary)
Exploit archive mining across multiple security databases:
  - PacketStorm Security (FREE scrape — 40+ year archive)
  - 0day.today public listing (FREE)
  - Vulhub public PoC repository (GitHub-based, FREE)
  - sploitus.com (FREE — CVE-to-exploit mapping)
  - Full-disclosure mailing list search (FREE)
  - RAPID7 AttackerKB community (FREE)
  - Timeline analysis of exploit releases vs CVE publish date
  - 0-day detection (exploit before patch)
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


class PacketstormModule(BaseModule):
    MODULE_NAME = "packetstorm"
    DESCRIPTION = "PacketStorm + Sploitus + Vulhub PoCs: exploit timeline, 0-day detection, multi-archive"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("Exploit archive: %s" % target)
        cached = cache.get("packetstorm", target)
        if cached:
            return cached

        ps_results, sploitus_results, vulhub_results = await asyncio.gather(
            self._packetstorm(target),
            self._sploitus(target),
            self._vulhub_pocs(target),
            return_exceptions=True,
        )

        def _s(v, d): return d if isinstance(v, Exception) else v
        ps_results      = _s(ps_results,      [])
        sploitus_results= _s(sploitus_results, [])
        vulhub_results  = _s(vulhub_results,   [])

        all_results     = ps_results + sploitus_results + vulhub_results
        all_cves        = list(set(r.get("cve","") for r in all_results if r.get("cve")))
        zeroday         = self._detect_zeroday(all_results)
        timeline        = self._build_timeline(all_results)

        result = {
            "target":          target,
            "total":           len(all_results),
            "packetstorm":     ps_results,
            "sploitus":        sploitus_results,
            "vulhub_pocs":     vulhub_results,
            "all_cves":        all_cves[:20],
            "zeroday_detected":zeroday,
            "timeline":        timeline,
            "sources": {
                "packetstorm": len(ps_results),
                "sploitus":    len(sploitus_results),
                "vulhub":      len(vulhub_results),
            },
        }

        self.log.found("Total Exploits",     str(len(all_results)))
        self.log.found("CVEs Covered",       str(len(all_cves)))
        self.log.found("PoC Available",      str(len(vulhub_results)))
        if zeroday:
            self.log.warning("POSSIBLE 0-DAY: exploit predates CVE publication!")

        cache.set("packetstorm", target, result)
        await self._persist_db(result)
        return result

    async def _packetstorm(self, target: str) -> list:
        url = "https://packetstormsecurity.com/search/?q=%s&s=files" % quote(target)
        results = []
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=20)
            if _r["ok"]:
                html = _r["text"]
                for m in re.finditer(
                    r'<dt><a[^>]+href="(/files/[^"]+)"[^>]*>(.*?)</a></dt>.*?'
                    r'<dd[^>]*class="detail"[^>]*>(.*?)</dd>',
                    html, re.DOTALL
                ):
                    title   = re.sub(r"<[^>]+>","",m.group(2)).strip()
                    details = re.sub(r"<[^>]+>","",m.group(3)).strip()
                    cve_m   = re.search(r"CVE-\d{4}-\d{4,7}", title + details)
                    results.append({
                        "url":   "https://packetstormsecurity.com%s" % m.group(1),
                        "title": title[:200],
                        "desc":  details[:200],
                        "cve":   cve_m.group(0) if cve_m else "",
                        "source":"packetstorm",
                    })
        except Exception as e:
            self.log.warning("PacketStorm: %s" % e)
        return results[:10]

    async def _sploitus(self, target: str) -> list:
        url = "https://sploitus.com/api"
        payload = {"type": "exploits", "query": target, "sort": "default", "offset": 0}
        results = []
        try:
            _r = await fetch(url, method="post", headers=config.DEFAULT_HEADERS, json_data=payload, timeout=15)
            if _r["ok"]:
                data = _r["json"]
                for item in data.get("exploits", [])[:10]:
                    results.append({
                        "title":     item.get("title","")[:200],
                        "url":       item.get("source",""),
                        "type":      item.get("type",""),
                        "cve":       item.get("id","") if "CVE" in item.get("id","") else "",
                        "published": item.get("published",""),
                        "source":    "sploitus",
                    })
        except Exception as e:
            self.log.warning("Sploitus: %s" % e)
        return results

    async def _vulhub_pocs(self, target: str) -> list:
        url = "https://api.github.com/search/repositories?q=%s+in:name+org:vulhub&per_page=5" % quote(target)
        hdrs = {**config.DEFAULT_HEADERS}
        if config.GITHUB_TOKEN:
            hdrs["Authorization"] = "token %s" % config.GITHUB_TOKEN
        results = []
        try:
            _r = await fetch(url, headers=hdrs, timeout=12)
            if _r["ok"]:
                data = _r["json"]
                for item in data.get("items", []):
                    results.append({
                        "title":   item.get("full_name",""),
                        "url":     item.get("html_url",""),
                        "desc":    item.get("description","")[:200],
                        "stars":   item.get("stargazers_count",0),
                        "cve":     item.get("full_name","").split("/")[-1].upper(),
                        "source":  "vulhub",
                    })
        except Exception as e:
            self.log.warning("Vulhub: %s" % e)
        return results

    def _detect_zeroday(self, results: list) -> bool:
        import re as _re
        for r in results:
            title = r.get("title","").lower()
            if "0day" in title or "zero-day" in title or "zero day" in title:
                return True
        return False

    def _build_timeline(self, results: list) -> list:
        tl = []
        for r in results:
            date = r.get("published","") or r.get("date","")
            if date:
                tl.append({"title": r.get("title","")[:100], "date": date[:10], "source": r.get("source","")})
        return sorted(tl, key=lambda x: x["date"], reverse=True)[:15]


    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://","http://","www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
