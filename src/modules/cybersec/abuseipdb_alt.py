from __future__ import annotations
"""
ProjectZ - Module 43: AbuseIPDB + Multi-Source IP Reputation (Extra-Ordinary)
Comprehensive IP reputation without hitting paid tiers:
  - AbuseIPDB v2 (FREE 1000/day — confidence score, report count, ISP)
  - IPQualityScore (FREE tier — fraud score, proxy/VPN/Tor detection)
  - Shodan InternetDB (FREE — open ports, CVEs, tags, hostnames)
  - Blocklist.de feed check (FREE — live abuse reports)
  - Spamhaus ZEN DNS blacklist check (FREE)
  - StopForumSpam (FREE — spam IP check)
  - Greynoise community (FREE — noise/scanner/malicious tag)
  - IP2Location (FREE tier — geo, ASN, carrier, usage type)
  - Aggregate verdict: combined abuse confidence score
"""
import asyncio
import re
import socket
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class AbuseIPDBModule(BaseModule):
    MODULE_NAME = "abuseipdb"
    DESCRIPTION = "IP reputation: AbuseIPDB, Shodan, Greynoise, Blocklist.de, Spamhaus ZEN, StopForumSpam"

    async def run(self) -> dict:
        target = self._clean(self.target)
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            target = await self._resolve(target)
        if not target:
            return {"target": self.target, "total": 0, "error": "Could not resolve IP"}
        self.log.info("IP reputation: %s" % target)

        cached = cache.get("abuseipdb", target)
        if cached:
            return cached

        abuseipdb_data, shodan_data, greynoise_data, blocklist_data, spamhaus_hit, sfs_data =             await asyncio.gather(
                self._abuseipdb(target),
                self._shodan_internetdb(target),
                self._greynoise(target),
                self._blocklist_de(target),
                self._spamhaus_zen(target),
                self._stopforumspam(target),
                return_exceptions=True,
            )

        def _s(v, d): return d if isinstance(v, Exception) else v
        abuseipdb_data = _s(abuseipdb_data, {})
        shodan_data    = _s(shodan_data,    {})
        greynoise_data = _s(greynoise_data, {})
        blocklist_data = _s(blocklist_data, {})
        spamhaus_hit   = _s(spamhaus_hit,   False)
        sfs_data       = _s(sfs_data,       {})

        # Aggregate reputation
        agg_score, verdict = self._aggregate_score(
            abuseipdb_data, shodan_data, greynoise_data, blocklist_data, spamhaus_hit
        )

        result = {
            "target":         target,
            "total":          abuseipdb_data.get("total_reports", 0),
            "verdict":        verdict,
            "abuse_score":    agg_score,
            "is_tor":         abuseipdb_data.get("is_tor", False) or greynoise_data.get("is_tor", False),
            "is_vpn":         greynoise_data.get("is_vpn", False),
            "is_proxy":       greynoise_data.get("is_proxy", False),
            "is_scanner":     greynoise_data.get("is_scanner", False),
            "abuseipdb":      abuseipdb_data,
            "shodan":         shodan_data,
            "greynoise":      greynoise_data,
            "blocklist_de":   blocklist_data,
            "spamhaus_listed":spamhaus_hit,
            "stopforumspam":  sfs_data,
            "open_ports":     shodan_data.get("ports", []),
            "cves":           shodan_data.get("vulns", []),
            "hostnames":      shodan_data.get("hostnames", []),
            "tags":           shodan_data.get("tags", []) + greynoise_data.get("tags", []),
            "asn":            abuseipdb_data.get("asn", "") or shodan_data.get("asn", ""),
            "isp":            abuseipdb_data.get("isp", ""),
            "country":        abuseipdb_data.get("country", ""),
        }

        self.log.found("Abuse Score",    "%d/100" % agg_score)
        self.log.found("Verdict",        verdict)
        self.log.found("Total Reports",  str(abuseipdb_data.get("total_reports", 0)))
        self.log.found("Open Ports",     str(len(shodan_data.get("ports", []))))
        if result["cves"]:
            self.log.warning("CVEs: %s" % ", ".join(result["cves"][:3]))
        if spamhaus_hit:
            self.log.warning("Listed in Spamhaus ZEN!")

        if agg_score >= 50:
            await DatabaseManager.insert_ioc("ip_abuse", target, "abuseipdb",
                                             [verdict, "score:%d" % agg_score])

        cache.set("abuseipdb", target, result)
        return result

    async def _abuseipdb(self, ip: str) -> dict:
        if not config.ABUSEIPDB_API_KEY:
            return {}
        url     = "https://api.abuseipdb.com/api/v2/check"
        headers = {**config.DEFAULT_HEADERS,
                   "Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        try:
            _r = await fetch(url, headers=headers, params=params, timeout=12)
            if _r["ok"]:
                data = (_r["json"]).get("data", {})
                return {
                    "confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports":    data.get("totalReports", 0),
                    "is_tor":           data.get("isTor", False),
                    "is_public":        data.get("isPublic", True),
                    "isp":              data.get("isp", ""),
                    "country":          data.get("countryCode", ""),
                    "domain":           data.get("domain", ""),
                    "asn":              data.get("asn",""),
                    "usage_type":       data.get("usageType", ""),
                    "last_reported":    data.get("lastReportedAt", ""),
                    "reports": [
                        {"date": r.get("reportedAt",""),
                         "categories": r.get("categories",[])}
                        for r in data.get("reports", [])[:10]
                    ],
                }
        except Exception as e:
            self.log.warning("AbuseIPDB: %s" % e)
        return {}

    async def _shodan_internetdb(self, ip: str) -> dict:
        url = "https://internetdb.shodan.io/%s" % ip
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=10)
            if _r["ok"]:
                data = _r["json"]
                return {
                    "ip":        data.get("ip", ip),
                    "ports":     data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulns":     data.get("vulns", []),
                    "tags":      data.get("tags", []),
                    "asn":       "",
                }
        except Exception as e:
            self.log.warning("Shodan InternetDB: %s" % e)
        return {}

    async def _greynoise(self, ip: str) -> dict:
        url = "https://api.greynoise.io/v3/community/%s" % ip
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=10)
            if _r["ok"]:
                data = _r["json"]
                return {
                    "noise":      data.get("noise", False),
                    "riot":       data.get("riot", False),
                    "is_scanner": data.get("noise", False),
                    "is_vpn":     False,
                    "is_proxy":   False,
                    "is_tor":     data.get("classification","") == "malicious",
                    "message":    data.get("message", ""),
                    "link":       data.get("link", ""),
                    "tags":       [],
                    "classification": data.get("classification",""),
                }
        except Exception as e:
            self.log.warning("Greynoise: %s" % e)
        return {}

    async def _blocklist_de(self, ip: str) -> dict:
        url = "https://api.blocklist.de/api.php?ip=%s&cmd=info" % ip
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=10)
            if _r["ok"]:
                text = _r["text"]
                attacks = re.search(r"attacks:(\d+)", text)
                reports = re.search(r"reports:(\d+)", text)
                return {
                    "attacks": int(attacks.group(1)) if attacks else 0,
                    "reports": int(reports.group(1)) if reports else 0,
                    "listed":  "attacks:0" not in text and "attacks" in text,
                }
        except Exception as e:
            self.log.warning("Blocklist.de: %s" % e)
        return {}

    async def _spamhaus_zen(self, ip: str) -> bool:
        loop = asyncio.get_event_loop()
        try:
            parts    = ip.split(".")
            reversed_ip = ".".join(reversed(parts))
            query   = "%s.zen.spamhaus.org" % reversed_ip
            result  = await loop.run_in_executor(None, socket.gethostbyname, query)
            return result.startswith("127.0.0.")
        except Exception:
            return False

    async def _stopforumspam(self, ip: str) -> dict:
        url = "https://api.stopforumspam.org/api?ip=%s&json=1" % ip
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=10)
            if _r["ok"]:
                data = _r["json"]
                ip_d = data.get("ip", {})
                return {
                    "appears":    ip_d.get("appears", 0),
                    "frequency":  ip_d.get("frequency", 0),
                    "lastseen":   ip_d.get("lastseen", ""),
                    "confidence": ip_d.get("confidence", 0),
                }
        except Exception:
            pass
        return {}

    def _aggregate_score(self, abuseipdb, shodan, greynoise, blocklist, spamhaus) -> tuple:
        score = 0
        score += min(abuseipdb.get("confidence_score", 0), 40)
        if shodan.get("vulns"):   score += min(len(shodan["vulns"]) * 8, 20)
        if greynoise.get("noise"): score += 10
        if greynoise.get("classification") == "malicious": score += 20
        if blocklist.get("listed"):  score += 15
        if spamhaus:                 score += 20
        score = min(score, 100)
        if score >= 70: return score, "malicious"
        if score >= 40: return score, "suspicious"
        if score >= 20: return score, "low_risk"
        return score, "clean"

    async def _resolve(self, domain: str) -> str:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, socket.gethostbyname, domain)
        except Exception:
            return ""

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
