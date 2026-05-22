"""
ProjectZ - Module 44: AlienVault OTX Full Intelligence (Extra-Ordinary)
Deep OTX threat intelligence with free API:
  - Domain, IP, URL, hash indicator lookups across ALL sections
  - Pulse metadata: threat actors, malware families, TTPs, CVEs
  - Passive DNS history from OTX
  - URL list + malware sample list from associated pulses
  - Geo + ASN + reputation from OTX general section
  - Related indicators pivot (IP -> domains -> hashes)
  - MITRE ATT&CK TTP tagging from pulse descriptions
  - Confidence scoring based on pulse count + age
"""
import asyncio
import re
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

OTX_BASE     = "https://otx.alienvault.com/api/v1/indicators"
OTX_SECTIONS = {
    "domain": ["general", "geo", "malware", "url_list", "passive_dns"],
    "ip":     ["general", "geo", "malware", "url_list", "passive_dns", "reputation"],
    "hash":   ["general", "analysis"],
    "url":    ["general"],
}

MITRE_TACTICS = {
    "initial access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
    "privilege escalation": "TA0004", "defense evasion": "TA0005",
    "credential access": "TA0006", "discovery": "TA0007", "lateral movement": "TA0008",
    "collection": "TA0009", "command and control": "TA0011", "exfiltration": "TA0010",
    "impact": "TA0040",
}


class OTXModule(BaseModule):
    MODULE_NAME = "otx"
    DESCRIPTION = "AlienVault OTX: all sections, pulse intel, passive DNS, TTPs, MITRE tagging"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("OTX intelligence: %s" % target)
        cached = cache.get("otx", target)
        if cached:
            return cached

        target_type = self._classify(target)
        sections    = OTX_SECTIONS.get(target_type, OTX_SECTIONS["domain"])

        ep_map = {
            "domain": "%s/domain/%s" % (OTX_BASE, target),
            "ip":     "%s/IPv4/%s" % (OTX_BASE, target),
            "hash":   "%s/file/%s" % (OTX_BASE, target),
            "url":    "%s/url/%s" % (OTX_BASE, target),
        }
        base_url = ep_map.get(target_type, ep_map["domain"])

        sem  = asyncio.Semaphore(20)
        hdrs = {**config.DEFAULT_HEADERS}
        if config.OTX_API_KEY:
            hdrs["X-OTX-API-KEY"] = config.OTX_API_KEY

        section_data = {}

        async def _fetch(section: str):
            url = "%s/%s" % (base_url, section)
            async with sem:
                try:
                    _r = await fetch(url, headers=hdrs, timeout=8)

                    if _r["ok"]:
                        return section, _r["json"]
                except Exception as e:
                    self.log.warning("OTX section %s: %s" % (section, e))
            return section, {}

        results = await asyncio.gather(
            *[_fetch(s) for s in sections],
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, tuple):
                section_data[item[0]] = item[1]

        # Parse all sections
        parsed = self._parse_all(section_data, target)

        # Extract MITRE TTPs from pulse descriptions
        ttps = self._extract_ttps(parsed.get("pulse_descriptions", []))

        result = {
            "target":          target,
            "target_type":     target_type,
            "total":           parsed.get("pulse_count", 0),
            "pulse_count":     parsed.get("pulse_count", 0),
            "reputation":      parsed.get("reputation", 0),
            "country":         parsed.get("country", ""),
            "asn":             parsed.get("asn", ""),
            "malware_families":parsed.get("malware_families", []),
            "threat_actors":   parsed.get("threat_actors", []),
            "tags":            parsed.get("tags", [])[:30],
            "ttps":            ttps,
            "pulses":          parsed.get("pulses", [])[:10],
            "passive_dns":     parsed.get("passive_dns", [])[:20],
            "urls":            parsed.get("urls", [])[:20],
            "hashes":          parsed.get("hashes", [])[:10],
            "geo":             parsed.get("geo", {}),
            "confidence_score":self._confidence_score(parsed),
        }

        self.log.found("Pulse Count",     str(parsed.get("pulse_count", 0)))
        self.log.found("Malware Families",str(len(parsed.get("malware_families", []))))
        self.log.found("MITRE TTPs",      str(len(ttps)))
        if parsed.get("malware_families"):
            self.log.warning("Families: %s" % ", ".join(parsed["malware_families"][:3]))

        cache.set("otx", target, result)
        return result

    def _parse_all(self, sections: dict, target: str) -> dict:
        pulses       = []
        pulse_descs  = []
        tags         = []
        families     = []
        actors       = []
        passive_dns  = []
        urls         = []
        hashes       = []
        geo          = {}
        reputation   = 0

        gen = sections.get("general", {})
        if gen:
            pi = gen.get("pulse_info", {})
            for p in pi.get("pulses", []):
                pulses.append({
                    "name":        p.get("name",""),
                    "author":      p.get("author_name",""),
                    "tlp":         p.get("tlp",""),
                    "tags":        p.get("tags",[]),
                    "created":     p.get("created",""),
                    "description": p.get("description","")[:200],
                })
                pulse_descs.append(p.get("description",""))
                tags.extend(p.get("tags",[]))
                author = p.get("author_name","")
                if author and author not in actors:
                    actors.append(author)
            tags.extend(gen.get("tags", []))

        geo_d = sections.get("geo", {})
        if geo_d:
            geo = {
                "country":      geo_d.get("country_name",""),
                "country_code": geo_d.get("country_code",""),
                "city":         geo_d.get("city",""),
                "asn":          str(geo_d.get("asn","")),
                "org":          geo_d.get("organization",""),
            }

        for m in sections.get("malware", {}).get("data", []):
            dets = m.get("detections", {})
            fam  = next(iter(dets.values()), "")
            if fam and fam not in families:
                families.append(fam)
            sha = m.get("hash","")
            if sha:
                hashes.append(sha)

        for r in sections.get("passive_dns", {}).get("passive_dns", []):
            passive_dns.append({
                "address":    r.get("address",""),
                "hostname":   r.get("hostname",""),
                "first":      r.get("first",""),
                "last":       r.get("last",""),
            })

        for u in sections.get("url_list", {}).get("url_list", []):
            urls.append({
                "url":      u.get("url",""),
                "date":     u.get("date",""),
                "result":   u.get("result",{}).get("urlworker",{}).get("ip",""),
            })

        rep_d = sections.get("reputation", {})
        if rep_d:
            reputation = rep_d.get("reputation", 0) or 0

        return {
            "pulse_count":     len(pulses),
            "pulses":          pulses,
            "pulse_descriptions": pulse_descs,
            "tags":            list(set(tags)),
            "malware_families":families,
            "threat_actors":   actors,
            "passive_dns":     passive_dns,
            "urls":            urls,
            "hashes":          hashes,
            "geo":             geo,
            "asn":             geo.get("asn",""),
            "country":         geo.get("country",""),
            "reputation":      reputation,
        }

    def _extract_ttps(self, descriptions: list) -> list:
        ttps  = []
        text  = " ".join(descriptions).lower()
        for tactic, ta_id in MITRE_TACTICS.items():
            if tactic in text and ta_id not in ttps:
                ttps.append({"tactic": tactic.title(), "ta_id": ta_id})
        return ttps

    def _confidence_score(self, parsed: dict) -> int:
        score = 0
        score += min(parsed.get("pulse_count", 0) * 10, 50)
        score += min(len(parsed.get("malware_families", [])) * 10, 30)
        score += min(len(parsed.get("hashes", [])) * 5, 20)
        return min(score, 100)

    def _classify(self, t: str) -> str:
        import re as _re
        if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t): return "ip"
        if _re.match(r"^[a-f0-9]{32,64}$", t.lower()):                     return "hash"
        if t.startswith("http"):                                             return "url"
        return "domain"

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
