"""
ProjectZ - Module 09: SPF / DMARC / DKIM / MTA-STS Email Security
Full email security posture check — misconfiguration detection.
Self-coded using dnspython.
"""

from __future__ import annotations

import asyncio
import re

from src.core import dns_compat as dns

from src.core.engine import BaseModule
from src.core.storage import cache, DatabaseManager


class SPFDMARCModule(BaseModule):
    MODULE_NAME = "spfdmarc"
    DESCRIPTION = "Email security — SPF, DMARC, DKIM, MTA-STS, BIMI analysis"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Email security check: {domain}")

        cached = cache.get("spfdmarc", domain)
        if cached:
            return cached

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # All checks in parallel
        spf, dmarc, mx, mta_sts, bimi = await asyncio.gather(
            self._spf(resolver, domain),
            self._dmarc(resolver, domain),
            self._mx_check(resolver, domain),
            self._mta_sts(resolver, domain),
            self._bimi(resolver, domain),
            return_exceptions=True,
        )

        def _safe(v, default): return default if isinstance(v, Exception) else v

        spf     = _safe(spf,     {})
        dmarc   = _safe(dmarc,   {})
        mx      = _safe(mx,      {})
        mta_sts = _safe(mta_sts, {})
        bimi    = _safe(bimi,    {})

        # Security score 0-100
        score, issues = self._score(spf, dmarc, mx)

        result = {
            "domain":    domain,
            "total":       1,
            "spf":       spf,
            "dmarc":     dmarc,
            "mx":        mx,
            "mta_sts":   mta_sts,
            "bimi":      bimi,
            "security_score": score,
            "issues":    issues,
            "grade":     self._grade(score),
        }

        self._log_findings(result)
        cache.set("spfdmarc", domain, result)
        await self._persist_db(result)
        return result

    # ── SPF ────────────────────────────────────────────────────────────────
    async def _spf(self, resolver, domain: str) -> dict:
        try:
            ans  = await asyncio.wait_for(resolver.resolve(domain, "TXT"), timeout=3)
            txts = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in ans]
            spf_record = next((t for t in txts if t.startswith("v=spf1")), None)

            if not spf_record:
                return {"exists": False, "record": None, "issues": ["No SPF record found"]}

            issues = []
            # Check for +all (allow all — dangerous)
            if "+all" in spf_record:
                issues.append("CRITICAL: '+all' allows any server to send — open relay risk")
            if "?all" in spf_record:
                issues.append("WARNING: '?all' is neutral — weak policy")
            if "-all" not in spf_record and "~all" not in spf_record and "+all" not in spf_record:
                issues.append("WARNING: No 'all' mechanism — policy incomplete")

            # Count DNS lookups (max 10 allowed)
            lookups = len(re.findall(r"\b(include|redirect|a|mx|exists|ptr)\b", spf_record))
            if lookups > 10:
                issues.append(f"WARNING: {lookups} DNS lookups exceed RFC limit of 10")

            return {
                "exists":      True,
                "record":      spf_record,
                "policy":      self._spf_policy(spf_record),
                "mechanisms":  re.findall(r"[+~?-]?\w+:[^\s]+|\ball\b", spf_record),
                "dns_lookups": lookups,
                "issues":      issues,
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"exists": False, "record": None, "issues": ["No SPF record found"]}
        except Exception as e:
            return {"exists": False, "error": str(e), "issues": []}

    def _spf_policy(self, record: str) -> str:
        if "-all" in record: return "strict (-all)"
        if "~all" in record: return "softfail (~all)"
        if "?all" in record: return "neutral (?all)"
        if "+all" in record: return "pass (+all) — DANGEROUS"
        return "unknown"

    # ── DMARC ──────────────────────────────────────────────────────────────
    async def _dmarc(self, resolver, domain: str) -> dict:
        try:
            ans    = await asyncio.wait_for(resolver.resolve(f"_dmarc.{domain}", "TXT"), timeout=3)
            record = b"".join(ans[0].strings).decode("utf-8", errors="ignore")

            if not record.startswith("v=DMARC1"):
                return {"exists": False, "record": record, "issues": ["Invalid DMARC record"]}

            tags = dict(
                kv.split("=", 1) for kv in record.split(";")
                if "=" in kv
            )
            policy       = tags.get("p", "none").strip()
            sp_policy    = tags.get("sp", policy).strip()
            pct          = tags.get("pct", "100").strip()
            rua          = tags.get("rua", "").strip()
            ruf          = tags.get("ruf", "").strip()

            issues = []
            if policy == "none":
                issues.append("WARNING: DMARC policy is 'none' — no enforcement")
            if not rua:
                issues.append("INFO: No aggregate report address (rua) configured")
            if pct != "100":
                issues.append(f"INFO: DMARC only applied to {pct}% of messages")

            return {
                "exists":        True,
                "record":        record,
                "policy":        policy,
                "subdomain_policy": sp_policy,
                "pct":           pct,
                "rua":           rua,
                "ruf":           ruf,
                "adkim":         tags.get("adkim", "r").strip(),
                "aspf":          tags.get("aspf", "r").strip(),
                "issues":        issues,
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"exists": False, "record": None, "issues": ["No DMARC record found"]}
        except Exception as e:
            return {"exists": False, "error": str(e), "issues": []}

    # ── MX records ─────────────────────────────────────────────────────────
    async def _mx_check(self, resolver, domain: str) -> dict:
        try:
            ans = await asyncio.wait_for(resolver.resolve(domain, "MX"), timeout=3)
            mxs = sorted(
                [(r.preference, str(r.exchange).rstrip(".")) for r in ans],
                key=lambda x: x[0],
            )
            providers = self._detect_mx_provider(mxs)
            return {
                "records":     [{"priority": p, "host": h} for p, h in mxs],
                "count":       len(mxs),
                "providers":   providers,
            }
        except Exception:
            return {"records": [], "count": 0, "issues": ["No MX records"]}

    def _detect_mx_provider(self, mxs: list) -> list[str]:
        providers = []
        patterns  = {
            "google.com":      "Google Workspace",
            "googlemail.com":  "Google Workspace",
            "outlook.com":     "Microsoft 365",
            "protection.outlook.com": "Microsoft 365",
            "pphosted.com":    "Proofpoint",
            "mimecast.com":    "Mimecast",
            "mailprotect.de":  "MailProtect",
            "amazonaws.com":   "Amazon SES",
            "sendgrid.net":    "SendGrid",
            "mailgun.org":     "Mailgun",
        }
        for _, host in mxs:
            for pat, name in patterns.items():
                if pat in host.lower() and name not in providers:
                    providers.append(name)
        return providers

    # ── MTA-STS ────────────────────────────────────────────────────────────
    async def _mta_sts(self, resolver, domain: str) -> dict:
        try:
            ans    = await asyncio.wait_for(resolver.resolve(f"_mta-sts.{domain}", "TXT"), timeout=3)
            record = b"".join(ans[0].strings).decode("utf-8", errors="ignore")
            return {"exists": True, "record": record}
        except Exception:
            return {"exists": False}

    # ── BIMI ───────────────────────────────────────────────────────────────
    async def _bimi(self, resolver, domain: str) -> dict:
        try:
            ans    = await asyncio.wait_for(resolver.resolve(f"default._bimi.{domain}", "TXT"), timeout=3)
            record = b"".join(ans[0].strings).decode("utf-8", errors="ignore")
            return {"exists": True, "record": record}
        except Exception:
            return {"exists": False}

    # ── Score ──────────────────────────────────────────────────────────────
    def _score(self, spf: dict, dmarc: dict, mx: dict) -> tuple[int, list[str]]:
        score  = 0
        issues = []

        if spf.get("exists"):
            score += 30
            policy = spf.get("policy", "")
            if "strict" in policy:   score += 20
            elif "softfail" in policy: score += 10
            else:                      issues.append("SPF policy not strict")
        else:
            issues.append("No SPF record")

        if dmarc.get("exists"):
            score += 30
            policy = dmarc.get("policy", "none")
            if policy == "reject":   score += 20
            elif policy == "quarantine": score += 10
            else:                    issues.append("DMARC not enforced (policy=none)")
        else:
            issues.append("No DMARC record")

        for iss in spf.get("issues", []) + dmarc.get("issues", []):
            if "CRITICAL" in iss:
                score -= 20
                issues.append(iss)
            elif "WARNING" in iss:
                score -= 10
                issues.append(iss)

        return max(0, min(100, score)), issues

    def _grade(self, score: int) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

    def _log_findings(self, r: dict) -> None:
        grade = r.get("grade", "?")
        score = r.get("security_score", 0)
        self.log.found("Email Security Grade", f"{grade} ({score}/100)")
        self.log.found("SPF",   "✓ Exists" if r["spf"].get("exists") else "✗ Missing")
        self.log.found("DMARC", "✓ Exists" if r["dmarc"].get("exists") else "✗ Missing")
        for issue in r.get("issues", []):
            self.log.warning(issue)


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
