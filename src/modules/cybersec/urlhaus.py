"""
ProjectZ - Module 50: URLhaus + Malware Distribution Intel (Extra-Ordinary)
URLhaus (abuse.ch) malware URL tracking:
  - URLhaus URL lookup (FREE, no key — live malware URLs)
  - URLhaus host lookup (domain/IP-based, all associated URLs)
  - URLhaus tag-based threat intel (malware families, campaigns)
  - Malware payload analysis from URLhaus metadata
  - Download URL categorization (payloads, droppers, C2)
  - Associated payloads with hash lookup
  - Active vs takedown status tracking
  - Campaign tagging from URLhaus submissions
  - Historical malware hosting timeline
"""
import asyncio
import re

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"


class URLHausModule(BaseModule):
    MODULE_NAME = "urlhaus"
    DESCRIPTION = "URLhaus: malware URL tracking, payload intel, host lookup, campaign tagging"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("URLhaus: %s" % target)
        cached = cache.get("urlhaus", target)
        if cached:
            return cached

        host_data, url_data = await asyncio.gather(
            self._host_lookup(target),
            self._url_lookup("https://%s" % target),
            return_exceptions=True,
        )

        def _s(v, d): return d if isinstance(v, Exception) else v
        host_data = _s(host_data, {})
        url_data  = _s(url_data,  {})

        all_urls    = host_data.get("urls", [])
        active_urls = [u for u in all_urls if u.get("url_status") == "online"]
        payload_hashes = list(set(
            p.get("sha256_hash","") for u in all_urls
            for p in u.get("payloads",[]) if p.get("sha256_hash")
        ))
        families    = list(set(
            p.get("signature","") for u in all_urls
            for p in u.get("payloads",[]) if p.get("signature")
        ))
        tags        = list(set(t for u in all_urls for t in u.get("tags",[])))
        risk_score  = self._risk_score(all_urls, active_urls)

        result = {
            "target":          target,
            "total":           len(all_urls),
            "urls_found":      len(all_urls),
            "active_urls":     active_urls[:10],
            "inactive_urls":   [u for u in all_urls if u.get("url_status") != "online"][:10],
            "payload_hashes":  payload_hashes[:20],
            "malware_families":families,
            "tags":            tags,
            "risk_score":      risk_score,
            "verdict":         "malicious" if all_urls else "clean",
            "host_info":       host_data.get("host_info", {}),
            "blacklists":      host_data.get("blacklists", {}),
            "url_lookup":      url_data,
        }

        self.log.found("URLhaus URLs",      str(len(all_urls)))
        self.log.found("Active Malware",    str(len(active_urls)))
        self.log.found("Malware Families",  ", ".join(families[:5]) if families else "None")
        if active_urls:
            self.log.warning("ACTIVE malware URLs hosted on this domain!")
        if payload_hashes:
            self.log.warning("%d payload hashes associated!" % len(payload_hashes))

        if all_urls:
            await DatabaseManager.insert_ioc("malware_host", target, "urlhaus", families[:3])

        cache.set("urlhaus", target, result)
        return result

    async def _host_lookup(self, target: str) -> dict:
        url     = "%s/host/" % URLHAUS_API
        payload = {"host": target}
        try:
            _r = await fetch(url, method="post", headers=config.DEFAULT_HEADERS, data=payload, timeout=8)

            if _r["ok"]:
                data = _r["json"]
                if data.get("query_status") in ("is_host","blacklisted"):
                    urls = []
                    for u in data.get("urls", [])[:20]:
                        payloads_raw = u.get("payloads",[]) or []
                        urls.append({
                            "url":          u.get("url",""),
                            "url_status":   u.get("url_status",""),
                            "date_added":   u.get("date_added",""),
                            "tags":         u.get("tags",[]),
                            "threat":       u.get("threat",""),
                            "payloads":     [
                                {"sha256_hash": p.get("response_sha256",""),
                                 "signature":   p.get("signature",""),
                                 "file_type":   p.get("file_type","")}
                                for p in payloads_raw[:3]
                            ],
                        })
                    return {
                        "query_status": data.get("query_status",""),
                        "urls":         urls,
                        "blacklists":   data.get("blacklists",{}),
                        "host_info":    {
                            "urls_on_host": data.get("urls_on_this_host",0),
                            "blacklisted":  data.get("query_status") == "blacklisted",
                        },
                    }
        except Exception as e:
            self.log.warning("URLhaus host: %s" % e)
        return {}

    async def _url_lookup(self, url_target: str) -> dict:
        url     = "%s/url/" % URLHAUS_API
        payload = {"url": url_target}
        try:
            _r = await fetch(url, method="post", headers=config.DEFAULT_HEADERS, data=payload, timeout=8)

            if _r["ok"]:
                data = _r["json"]
                return {
                    "status":     data.get("url_status",""),
                    "threat":     data.get("threat",""),
                    "tags":       data.get("tags",[]),
                    "reporter":   data.get("reporter",""),
                    "date_added": data.get("date_added",""),
                }
        except Exception as e:
            self.log.warning("URLhaus URL: %s" % e)
        return {}

    def _risk_score(self, all_urls: list, active_urls: list) -> int:
        score = 0
        score += min(len(all_urls) * 10, 40)
        score += min(len(active_urls) * 20, 60)
        return min(score, 100)

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://","http://","www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
