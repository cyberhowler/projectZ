"""
ProjectZ - Module 46: HIBP Full Intelligence (Extra-Ordinary)
Complete Have I Been Pwned analysis:
  - HIBP breach lookup by domain (FREE v3 API)
  - HIBP paste search by email/domain (requires key)
  - Breach timeline + data class analysis
  - Pwned count aggregation + severity scoring
  - Custom email pattern generation for breach testing
  - Breach-to-date correlation (find oldest breach)
  - Data sensitivity classification
  - Actionable remediation recommendations
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

SENSITIVE_CLASSES = {
    "Passwords":                  "critical",
    "Credit cards":               "critical",
    "Social security numbers":    "critical",
    "Bank account numbers":       "critical",
    "Passport numbers":           "critical",
    "Email addresses":            "high",
    "Phone numbers":              "high",
    "Physical addresses":         "high",
    "Government issued IDs":      "high",
    "Sexual orientations":        "high",
    "Health insurance information":"high",
    "IP addresses":               "medium",
    "Usernames":                  "medium",
    "Dates of birth":             "medium",
    "Geographic locations":       "low",
    "Names":                      "low",
}


class HIBPModule(BaseModule):
    MODULE_NAME = "hibp"
    DESCRIPTION = "HIBP: domain breach search, paste hunt, timeline, data class sensitivity, remediation"

    async def run(self) -> dict:
        target = self._clean(self.target)
        self.log.info("HIBP: %s" % target)
        cached = cache.get("hibp", target)
        if cached:
            return cached

        all_breaches = await self._all_breaches()
        domain_breaches  = [b for b in all_breaches
                            if target in b.get("Domain","").lower() or
                               target in b.get("Name","").lower()]
        pastes = await self._paste_search(target) if config.HIBP_API_KEY else []

        # Data class analysis
        all_data_classes = list(set(
            dc for b in domain_breaches for dc in b.get("DataClasses",[])
        ))
        sensitivity_breakdown = self._classify_sensitivity(all_data_classes)
        total_pwned = sum(b.get("PwnCount",0) for b in domain_breaches)
        timeline    = self._timeline(domain_breaches)
        oldest      = min((b.get("BreachDate","9999") for b in domain_breaches), default="")
        severity    = self._severity(domain_breaches, all_data_classes)
        remediation = self._remediation(all_data_classes, severity)

        result = {
            "target":          target,
            "total":           len(domain_breaches),
            "breach_count":    len(domain_breaches),
            "paste_count":     len(pastes),
            "total_pwned":     total_pwned,
            "severity":        severity,
            "data_classes":    all_data_classes,
            "sensitivity":     sensitivity_breakdown,
            "breaches":        [self._format_breach(b) for b in domain_breaches],
            "timeline":        timeline,
            "oldest_breach":   oldest,
            "newest_breach":   max((b.get("BreachDate","") for b in domain_breaches), default=""),
            "pastes":          pastes[:10],
            "remediation":     remediation,
        }

        self.log.found("Breach Count",  str(len(domain_breaches)))
        self.log.found("Total Pwned",   "%s" % "{:,}".format(total_pwned))
        self.log.found("Severity",      severity.upper())
        if all_data_classes:
            self.log.found("Data Classes", ", ".join(all_data_classes[:5]))
        if "Passwords" in all_data_classes:
            self.log.warning("PASSWORDS EXPOSED in breaches!")

        cache.set("hibp", target, result)
        return result

    async def _all_breaches(self) -> list:
        url  = "https://haveibeenpwned.com/api/v3/breaches"
        hdrs = {**config.DEFAULT_HEADERS, "user-agent": "ProjectZ-OSINT"}
        if config.HIBP_API_KEY:
            hdrs["hibp-api-key"] = config.HIBP_API_KEY
        try:
            _r = await fetch(url, headers=hdrs, timeout=8)
            if _r["ok"] and _r["json"]:
                return _r["json"]
        except Exception as e:
            self.log.warning("HIBP: %s" % e)
        return []

    async def _paste_search(self, domain: str) -> list:
        if not config.HIBP_API_KEY:
            return []
        url  = "https://haveibeenpwned.com/api/v3/pasteaccount/admin%%40%s" % domain
        hdrs = {**config.DEFAULT_HEADERS, "hibp-api-key": config.HIBP_API_KEY,
                "user-agent": "ProjectZ-OSINT"}
        try:
            _r = await fetch(url, headers=hdrs, timeout=8)
            if _r["ok"] and _r["json"]:
                return _r["json"]
        except Exception:
            pass
        return []

    def _format_breach(self, b: dict) -> dict:
        desc = re.sub(r"<[^>]+>", "", b.get("Description",""))[:300]
        return {
            "name":          b.get("Name",""),
            "title":         b.get("Title",""),
            "domain":        b.get("Domain",""),
            "date":          b.get("BreachDate",""),
            "added":         b.get("AddedDate",""),
            "pwn_count":     b.get("PwnCount",0),
            "data_classes":  b.get("DataClasses",[]),
            "verified":      b.get("IsVerified",False),
            "fabricated":    b.get("IsFabricated",False),
            "sensitive":     b.get("IsSensitive",False),
            "description":   desc,
        }

    def _classify_sensitivity(self, data_classes: list) -> dict:
        breakdown = {"critical": [], "high": [], "medium": [], "low": []}
        for dc in data_classes:
            level = SENSITIVE_CLASSES.get(dc, "low")
            breakdown[level].append(dc)
        return breakdown

    def _timeline(self, breaches: list) -> list:
        return sorted(
            [{"name": b.get("Name",""), "date": b.get("BreachDate",""),
              "pwn_count": b.get("PwnCount",0),
              "data_classes": b.get("DataClasses",[])[:3]}
             for b in breaches],
            key=lambda x: x["date"], reverse=True
        )[:20]

    def _severity(self, breaches: list, data_classes: list) -> str:
        if "Passwords" in data_classes or "Credit cards" in data_classes: return "critical"
        if len(breaches) >= 5:     return "high"
        if len(breaches) >= 2:     return "medium"
        if len(breaches) >= 1:     return "low"
        return "clean"

    def _remediation(self, data_classes: list, severity: str) -> list:
        recs = []
        if "Passwords" in data_classes:
            recs.append("Force password reset for all users immediately")
            recs.append("Implement multi-factor authentication (MFA)")
        if "Credit cards" in data_classes:
            recs.append("Notify payment processor and affected card holders")
            recs.append("Assess PCI DSS compliance")
        if severity in ("critical","high"):
            recs.append("Notify affected users per GDPR/CCPA requirements")
            recs.append("Engage incident response team")
        recs.append("Monitor dark web for credential dumps")
        recs.append("Enable breach notification alerts via HIBP")
        return recs

    def _clean(self, t: str) -> str:
        t = t.strip()
        if "@" in t: return t.split("@")[1].lower()
        for p in ("https://","http://","www."):
            if t.lower().startswith(p): t = t[len(p):]
        return t.split("/")[0].lower()
