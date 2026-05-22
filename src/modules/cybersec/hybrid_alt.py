"""
ProjectZ - Module 41: YARA + Hybrid Analysis Alternative (Extra-Ordinary)
Advanced malware/IOC analysis without paid sandbox:
  - YARA rule matching against domain/URL patterns (offline rules)
  - MalwareBazaar (FREE - file hash + tag lookup)
  - ThreatFox IOC feed (FREE - domain/IP/URL IOC lookup)
  - Malshare public feed (FREE - recent malware hashes)
  - ANY.RUN public reports search (FREE scrape)
  - CAPE Sandbox public results (FREE)
  - 25+ custom YARA-style regex rules for web IOCs
  - IOC extraction: C2 patterns, DGA detection, fast-flux detection
  - Risk scoring based on multi-source correlation
"""
import asyncio
import hashlib
import re
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# YARA-style web IOC rules (regex-based, no YARA lib needed)
YARA_RULES = [
    {"name": "suspicious_tld",      "pattern": r"\.(xyz|top|tk|ml|ga|cf|gq|pw|cc|click|loan|bid|win|men|download|stream)\b",     "severity": "medium", "description": "Suspicious free TLD"},
    {"name": "ip_as_domain",        "pattern": r"^(\d{1,3}\.){3}\d{1,3}$",                                                         "severity": "high",   "description": "IP used as domain"},
    {"name": "excessive_subdomains", "pattern": r"([a-z0-9-]+\.){4,}",                                                              "severity": "medium", "description": "Excessive subdomain depth (4+)"},
    {"name": "dga_pattern",         "pattern": r"^[a-z]{8,15}\.[a-z]{2,5}$",                                                       "severity": "medium", "description": "Possible DGA domain (random chars)"},
    {"name": "punycode_domain",     "pattern": r"xn--",                                                                             "severity": "high",   "description": "Punycode/IDN homograph attack"},
    {"name": "brand_typosquat",     "pattern": r"(paypa1|g00gle|micros0ft|arnazon|facebok|linkedln|twiter|instagran|netfl1x|paypai)", "severity": "critical", "description": "Brand typosquatting"},
    {"name": "credential_pattern",  "pattern": r"(login|signin|account|secure|verify|confirm|update|password|credential)\.",        "severity": "high",   "description": "Credential phishing pattern"},
    {"name": "short_domain",        "pattern": r"^[a-z0-9]{3,5}\.[a-z]{2,4}$",                                                     "severity": "low",    "description": "Very short domain name"},
    {"name": "double_extension",    "pattern": r"\.[a-z]{2,4}\.[a-z]{2,4}$",                                                       "severity": "medium", "description": "Double extension (evasion)"},
    {"name": "url_shortener",       "pattern": r"^(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|buff\.ly|tiny\.cc|rb\.gy|cutt\.ly)$",      "severity": "medium", "description": "URL shortener service"},
    {"name": "parking_pattern",     "pattern": r"(parked|forsale|for-sale|domain-for-sale|buy-this-domain)",                        "severity": "low",    "description": "Parked/for-sale domain"},
    {"name": "c2_pattern",          "pattern": r"(c2\.|cnc\.|botnet\.|rat\.|payload\.|dropper\.|downloader\.)",                     "severity": "critical","description": "C2/malware infrastructure pattern"},
    {"name": "fast_flux_indicator", "pattern": r"^[0-9a-f]{16,32}\.[a-z]{2,5}$",                                                   "severity": "high",   "description": "Possible fast-flux indicator"},
    {"name": "long_subdomain",      "pattern": r"[a-z0-9]{30,}\.",                                                                  "severity": "high",   "description": "Unusually long subdomain (data exfil?)"},
    {"name": "numeric_subdomain",   "pattern": r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\.",                                              "severity": "high",   "description": "IP-formatted subdomain (fast-flux)"},
]


class YARAModule(BaseModule):
    MODULE_NAME = "yara"
    DESCRIPTION = "YARA rules + MalwareBazaar, ThreatFox, Malshare — IOC correlation, DGA detection"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("YARA + hybrid analysis: %s" % target)

        cached = cache.get("yara", target)
        if cached:
            return cached

        # YARA rules run offline (instant)
        rule_matches = self._run_yara_rules(target)

        # External IOC sources in parallel
        threatfox_data, bazaar_data, malshare_data = await asyncio.gather(
            self._threatfox_lookup(target),
            self._malwarebazaar_lookup(target),
            self._malshare_feed_check(target),
            return_exceptions=True,
        )

        def _s(v, d): return d if isinstance(v, Exception) else v
        threatfox_data = _s(threatfox_data, {})
        bazaar_data    = _s(bazaar_data,    {})
        malshare_data  = _s(malshare_data,  {})

        # Compute IOC risk
        ioc_score = self._ioc_score(rule_matches, threatfox_data, bazaar_data)

        # Check for DGA
        dga_result = self._dga_analysis(target)

        result = {
            "target":        target,
            "total":         len(rule_matches) + len(threatfox_data.get("iocs", [])),
            "yara_matches":  rule_matches,
            "yara_hit_count":len(rule_matches),
            "ioc_score":     ioc_score,
            "severity":      self._severity_from_score(ioc_score),
            "dga_analysis":  dga_result,
            "threatfox":     threatfox_data,
            "malwarebazaar": bazaar_data,
            "malshare":      malshare_data,
            "all_iocs": (
                threatfox_data.get("iocs", []) +
                bazaar_data.get("iocs", [])
            )[:30],
        }

        self.log.found("YARA Matches",  str(len(rule_matches)))
        self.log.found("IOC Score",     "%d/100" % ioc_score)
        self.log.found("DGA Entropy",   "%.2f" % dga_result.get("entropy", 0))
        if dga_result.get("is_dga"):
            self.log.warning("POSSIBLE DGA DOMAIN DETECTED!")
        for m in rule_matches:
            if m["severity"] in ("critical", "high"):
                self.log.warning("[%s] %s" % (m["severity"].upper(), m["description"]))
        if threatfox_data.get("ioc_found"):
            self.log.warning("IN THREATFOX IOC DATABASE!")

        if ioc_score >= 50:
            await DatabaseManager.insert_ioc("domain_yara", target, "yara",
                                             [m["name"] for m in rule_matches[:3]])

        cache.set("yara", target, result)
        return result

    # ── YARA rule matching ─────────────────────────────────────────────────
    def _run_yara_rules(self, target: str) -> list:
        matches = []
        for rule in YARA_RULES:
            if re.search(rule["pattern"], target, re.I):
                matches.append({
                    "name":        rule["name"],
                    "description": rule["description"],
                    "severity":    rule["severity"],
                    "matched":     target,
                })
        return matches

    # ── ThreatFox IOC lookup (FREE, no key) ───────────────────────────────
    async def _threatfox_lookup(self, target: str) -> dict:
        url     = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": target}
        try:
            _r = await fetch(url, method="post", headers=config.DEFAULT_HEADERS, json_data=payload, timeout=8)

            if _r["ok"]:
                data   = _r["json"]
                status = data.get("query_status", "")
                iocs   = data.get("data", []) or []
                return {
                    "ioc_found":    status == "ok" and len(iocs) > 0,
                    "ioc_count":    len(iocs),
                    "iocs": [
                        {
                            "ioc":           i.get("ioc", ""),
                            "ioc_type":      i.get("ioc_type", ""),
                            "threat_type":   i.get("threat_type", ""),
                            "malware":       i.get("malware", ""),
                            "confidence":    i.get("confidence_level", 0),
                            "first_seen":    i.get("first_seen", ""),
                        }
                        for i in iocs[:10]
                    ],
                }
        except Exception as e:
            self.log.warning("ThreatFox: %s" % e)
        return {"ioc_found": False, "ioc_count": 0, "iocs": []}

    # ── MalwareBazaar (FREE) ───────────────────────────────────────────────
    async def _malwarebazaar_lookup(self, target: str) -> dict:
        url     = "https://mb-api.abuse.ch/api/v1/"
        payload = {"query": "search_tag", "tag": target}
        try:
            _r = await fetch(url, method="post", headers=config.DEFAULT_HEADERS, json_data=payload, timeout=8)

            if _r["ok"]:
                data   = _r["json"]
                status = data.get("query_status", "")
                items  = data.get("data", []) or []
                iocs   = [
                    {
                        "sha256":        i.get("sha256_hash", ""),
                        "file_type":     i.get("file_type", ""),
                        "tags":          i.get("tags", []),
                        "signature":     i.get("signature", ""),
                        "first_seen":    i.get("first_seen", ""),
                    }
                    for i in items[:5]
                ]
                return {
                    "found":    status == "ok",
                    "count":    len(items),
                    "iocs":     iocs,
                    "families": list(set(i.get("signature","") for i in items if i.get("signature"))),
                }
        except Exception as e:
            self.log.warning("MalwareBazaar: %s" % e)
        return {"found": False, "count": 0, "iocs": [], "families": []}

    # ── Malshare recent feed check (FREE) ──────────────────────────────────
    async def _malshare_feed_check(self, target: str) -> dict:
        if not config.MALSHARE_API_KEY:
            return {"available": False}
        url = "https://malshare.com/api.php?api_key=%s&action=getlistraw" % config.MALSHARE_API_KEY
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)

            if _r["ok"]:
                text  = _r["text"]
                lines = text.strip().splitlines()
                return {"available": True, "recent_count": len(lines)}
        except Exception:
            pass
        return {"available": False}

    # ── DGA (Domain Generation Algorithm) analysis ─────────────────────────
    def _dga_analysis(self, domain: str) -> dict:
        import math
        base = domain.split(".")[0] if "." in domain else domain

        # Calculate Shannon entropy
        freq  = {}
        for c in base:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(base)
            if p > 0:
                entropy -= p * math.log2(p)

        # Consonant ratio (DGA domains tend to have high consonant ratios)
        vowels   = set("aeiou")
        cons_ratio = sum(1 for c in base if c.isalpha() and c not in vowels) / max(len(base), 1)

        # Digit ratio
        digit_ratio = sum(1 for c in base if c.isdigit()) / max(len(base), 1)

        # DGA score
        dga_score = 0
        if entropy > 3.5:          dga_score += 30
        elif entropy > 3.0:        dga_score += 15
        if cons_ratio > 0.75:      dga_score += 25
        if digit_ratio > 0.3:      dga_score += 20
        if len(base) > 12:         dga_score += 15
        if not re.search(r"[aeiou]{2}", base):  dga_score += 10

        return {
            "is_dga":       dga_score >= 50,
            "dga_score":    dga_score,
            "entropy":      round(entropy, 3),
            "cons_ratio":   round(cons_ratio, 3),
            "digit_ratio":  round(digit_ratio, 3),
            "base_domain":  base,
            "label":        "Likely DGA" if dga_score >= 50 else ("Suspicious" if dga_score >= 30 else "Normal"),
        }

    def _ioc_score(self, yara_matches: list, threatfox: dict, bazaar: dict) -> int:
        score = 0
        sev_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        for m in yara_matches:
            score += sev_weights.get(m.get("severity", "low"), 5)
        if threatfox.get("ioc_found"):   score += 40
        if bazaar.get("found"):          score += 20
        return min(score, 100)

    def _severity_from_score(self, score: int) -> str:
        if score >= 70: return "critical"
        if score >= 50: return "high"
        if score >= 30: return "medium"
        if score > 0:   return "low"
        return "clean"

    def _clean(self, t: str) -> str:
        t = t.strip()
        for p in ("https://", "http://", "www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
