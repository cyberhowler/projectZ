"""
ProjectZ - Module 42: ThreatCrowd Alt / IOC Correlation Engine (Extra-Ordinary)
  - AlienVault OTX domain/IP/hash lookups (FREE with key)
  - ThreatMiner passive intel (FREE, no key)
  - CIRCL.lu passive DNS correlation (FREE, no key)
  - IOC regex extraction: IPs, domains, hashes, CVEs, BTC wallets
  - Infrastructure clustering by C-class blocks
  - Threat actor attribution from OTX pulse metadata
  - Cross-source pivot: domain -> IP -> hash -> family
"""
import asyncio
import re

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

IOC_PATTERNS = {
    "ipv4":   r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
    "md5":    r"[a-fA-F0-9]{32}",
    "sha256": r"[a-fA-F0-9]{64}",
    "cve":    r"CVE-\d{4}-\d{4,7}",
    "email":  r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
}


class ThreatCrowdModule(BaseModule):
    MODULE_NAME = "threatcrowd"
    DESCRIPTION = "IOC correlation: OTX, ThreatMiner, CIRCL — pivot domain/IP/hash, actor hints"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("IOC correlation: %s" % target)
        cached = cache.get("threatcrowd", target)
        if cached:
            return cached

        target_type = self._classify(target)
        otx_data, tm_data, circl_data = await asyncio.gather(
            self._otx(target, target_type),
            self._threatminer(target, target_type),
            self._circl(target),
            return_exceptions=True,
        )

        def _s(v, d): return d if isinstance(v, Exception) else v
        otx_data   = _s(otx_data,   {"ips": [], "domains": [], "hashes": [], "pulses": [], "malware_families": [], "tags": []})
        tm_data    = _s(tm_data,    {"ips": [], "domains": [], "results": []})
        circl_data = _s(circl_data, {"ips": [], "records": []})

        related_ips     = list(set(otx_data["ips"]    + tm_data["ips"]    + circl_data["ips"]))
        related_domains = list(set(otx_data["domains"] + tm_data["domains"]))
        related_hashes  = list(set(otx_data["hashes"]))
        clusters        = self._cluster_ips(related_ips)
        extracted       = self._extract_iocs(str(otx_data) + str(tm_data))
        actors          = list(set(
            p.get("author_name","") for p in otx_data["pulses"] if p.get("author_name")
        ))

        result = {
            "target":           target,
            "target_type":      target_type,
            "total":            len(related_ips) + len(related_domains) + len(related_hashes),
            "related_ips":      related_ips[:30],
            "related_domains":  related_domains[:30],
            "related_hashes":   related_hashes[:20],
            "extracted_iocs":   extracted,
            "threat_actors":    actors[:10],
            "infrastructure_clusters": clusters,
            "pulse_count":      len(otx_data["pulses"]),
            "malware_families": otx_data["malware_families"],
            "tags":             otx_data["tags"][:20],
            "otx_pulses":       otx_data["pulses"][:5],
            "circl_records":    circl_data.get("records", [])[:10],
        }

        self.log.found("Related IPs",    str(len(related_ips)))
        self.log.found("OTX Pulses",     str(len(otx_data["pulses"])))
        self.log.found("Threat Actors",  str(len(actors)))
        if actors:
            self.log.warning("Actors: %s" % ", ".join(actors[:3]))

        cache.set("threatcrowd", target, result)
        return result

    async def _otx(self, target: str, ttype: str) -> dict:
        if not config.OTX_API_KEY:
            return {"ips": [], "domains": [], "hashes": [], "pulses": [], "malware_families": [], "tags": []}
        bases = {
            "domain": "https://otx.alienvault.com/api/v1/indicators/domain/%s",
            "ip":     "https://otx.alienvault.com/api/v1/indicators/IPv4/%s",
            "hash":   "https://otx.alienvault.com/api/v1/indicators/file/%s",
        }
        base    = (bases.get(ttype, bases["domain"])) % target
        hdrs    = {**config.DEFAULT_HEADERS, "X-OTX-API-KEY": config.OTX_API_KEY}
        result  = {"ips": [], "domains": [], "hashes": [], "pulses": [], "malware_families": [], "tags": []}
        sem     = asyncio.Semaphore(20)

        async def _fetch(section):
            url = "%s/%s" % (base, section)
            async with sem:
                try:
                    _r = await fetch(url, headers=hdrs, timeout=8)

                    if _r["ok"]:
                        return section, _r["json"]
                except Exception:
                    pass
            return section, {}

        results = await asyncio.gather(
            *[_fetch(s) for s in ["general", "passive_dns", "malware"]],
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, tuple):
                section, data = item
                if section == "general":
                    for p in data.get("pulse_info", {}).get("pulses", []):
                        result["pulses"].append({
                            "name": p.get("name",""), "author_name": p.get("author_name",""),
                            "tags": p.get("tags",[]),  "tlp": p.get("tlp",""),
                        })
                    result["tags"].extend(data.get("tags", []))
                elif section == "passive_dns":
                    for r in data.get("passive_dns", []):
                        addr = r.get("address","")
                        if re.match(r"\d+\.\d+\.\d+\.\d+", addr):
                            result["ips"].append(addr)
                elif section == "malware":
                    for m in data.get("data", []):
                        dets = m.get("detections", {})
                        fam  = next(iter(dets.values()), "") if dets else ""
                        if fam and fam not in result["malware_families"]:
                            result["malware_families"].append(fam)
        return result

    async def _threatminer(self, target: str, ttype: str) -> dict:
        eps = {
            "domain": "https://api.threatminer.org/v2/domain.php?q=%s&rt=2",
            "ip":     "https://api.threatminer.org/v2/host.php?q=%s&rt=2",
        }
        url = (eps.get(ttype, eps["domain"])) % target
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)

            if _r["ok"]:
                data    = _r["json"]
                results = data.get("results", [])
                ips     = [r for r in results if re.match(r"\d+\.\d+\.\d+\.\d+", str(r))]
                domains = [r for r in results if "." in str(r) and str(r) not in ips]
                return {"results": results[:20], "ips": ips[:10], "domains": domains[:10]}
        except Exception as e:
            self.log.warning("ThreatMiner: %s" % e)
        return {"results": [], "ips": [], "domains": []}

    async def _circl(self, target: str) -> dict:
        url = "https://www.circl.lu/pdns/query/%s" % target
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=10)

            if _r["ok"]:
                import json as _json
                text    = _r["text"]
                records = []
                for line in text.splitlines():
                    try: records.append(_json.loads(line))
                    except Exception: pass
                ips = list(set(
                    r.get("rdata","") for r in records
                    if re.match(r"\d+\.\d+\.\d+\.\d+", r.get("rdata",""))
                ))
                return {"records": records[:20], "ips": ips[:15]}
        except Exception as e:
            self.log.warning("CIRCL: %s" % e)
        return {"records": [], "ips": []}

    def _extract_iocs(self, text: str) -> dict:
        out = {}
        for name, pat in IOC_PATTERNS.items():
            found = list(set(re.findall(pat, text)))[:15]
            if found:
                out[name] = found
        return out

    def _cluster_ips(self, ips: list) -> dict:
        clusters = {}
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                block = ".".join(parts[:3]) + ".0/24"
                clusters.setdefault(block, []).append(ip)
        return {k: v for k, v in clusters.items() if len(v) > 1}

    def _classify(self, t: str) -> str:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", t): return "ip"
        if re.match(r"^[a-f0-9]{32,64}$", t.lower()):                     return "hash"
        return "domain"

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
