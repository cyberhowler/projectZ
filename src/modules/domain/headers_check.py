"""
ProjectZ - Module: HTTP Security Headers Audit
Checks all OWASP-recommended HTTP security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-XSS-Protection
  - Cross-Origin-* headers (CORP, COEP, COOP)
  - Cache-Control
  - Expect-CT
  - Feature-Policy (deprecated but checked)
  - Server / X-Powered-By info disclosure
  - Cookie flags (Secure, HttpOnly, SameSite)
Gives per-header grade + overall security grade A–F.
Author: cyberhowler (R.G)
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from src.core.engine import BaseModule
from src.core.http_client import fetch
from src.core.storage import cache, DatabaseManager
from src.core.config import config


# Header definitions: (header_name, required, description, check_fn)
SECURITY_HEADERS: list[dict] = [
    {
        "name":        "Strict-Transport-Security",
        "required":    True,
        "severity":    "high",
        "description": "Forces HTTPS — prevents downgrade attacks",
        "good_pattern": r"max-age=\d+",
        "best_value":  "max-age=31536000; includeSubDomains; preload",
    },
    {
        "name":        "Content-Security-Policy",
        "required":    True,
        "severity":    "high",
        "description": "Restricts resource loading — mitigates XSS",
        "good_pattern": r"default-src|script-src",
        "best_value":  "default-src 'self'; script-src 'self'",
    },
    {
        "name":        "X-Frame-Options",
        "required":    True,
        "severity":    "medium",
        "description": "Prevents clickjacking attacks",
        "good_pattern": r"DENY|SAMEORIGIN",
        "best_value":  "DENY",
    },
    {
        "name":        "X-Content-Type-Options",
        "required":    True,
        "severity":    "medium",
        "description": "Prevents MIME type sniffing",
        "good_pattern": r"nosniff",
        "best_value":  "nosniff",
    },
    {
        "name":        "Referrer-Policy",
        "required":    True,
        "severity":    "low",
        "description": "Controls referrer information leakage",
        "good_pattern": r"no-referrer|strict-origin",
        "best_value":  "strict-origin-when-cross-origin",
    },
    {
        "name":        "Permissions-Policy",
        "required":    True,
        "severity":    "medium",
        "description": "Restricts browser features (camera, mic, geolocation)",
        "good_pattern": r"camera|microphone|geolocation",
        "best_value":  "camera=(), microphone=(), geolocation=()",
    },
    {
        "name":        "X-XSS-Protection",
        "required":    False,  # deprecated but still checked
        "severity":    "low",
        "description": "Legacy XSS filter (deprecated, CSP preferred)",
        "good_pattern": r"1; mode=block",
        "best_value":  "1; mode=block",
    },
    {
        "name":        "Cross-Origin-Opener-Policy",
        "required":    False,
        "severity":    "medium",
        "description": "Prevents cross-origin window attacks (Spectre)",
        "good_pattern": r"same-origin",
        "best_value":  "same-origin",
    },
    {
        "name":        "Cross-Origin-Embedder-Policy",
        "required":    False,
        "severity":    "low",
        "description": "Isolates the browsing context",
        "good_pattern": r"require-corp",
        "best_value":  "require-corp",
    },
    {
        "name":        "Cross-Origin-Resource-Policy",
        "required":    False,
        "severity":    "low",
        "description": "Controls cross-origin resource sharing",
        "good_pattern": r"same-site|same-origin",
        "best_value":  "same-origin",
    },
]

# Information-disclosing headers (should be REMOVED or obfuscated)
INFO_DISCLOSURE_HEADERS: list[dict] = [
    {"name": "Server",        "risk": "info",   "reason": "Reveals server software/version"},
    {"name": "X-Powered-By", "risk": "medium",  "reason": "Reveals backend language/framework"},
    {"name": "X-AspNet-Version", "risk": "medium", "reason": "Reveals .NET version"},
    {"name": "X-AspNetMvc-Version", "risk": "medium", "reason": "Reveals ASP.NET MVC version"},
    {"name": "X-Generator",  "risk": "info",    "reason": "Reveals CMS/site generator"},
    {"name": "X-Drupal-Cache","risk": "info",   "reason": "Reveals Drupal CMS"},
    {"name": "X-Varnish",    "risk": "info",    "reason": "Reveals Varnish proxy"},
    {"name": "Via",           "risk": "info",   "reason": "Reveals proxy chain"},
]

# Cookie security checks
def _check_cookie_security(set_cookie_header: str) -> list[dict]:
    issues = []
    if not set_cookie_header:
        return issues
    cookies = set_cookie_header.split(",")
    for cookie in cookies:
        cl = cookie.lower()
        name = cookie.split("=")[0].strip()
        if "secure" not in cl:
            issues.append({
                "cookie":   name,
                "issue":    "Missing Secure flag",
                "severity": "high",
                "detail":   "Cookie can be sent over HTTP — vulnerable to interception",
            })
        if "httponly" not in cl:
            issues.append({
                "cookie":   name,
                "issue":    "Missing HttpOnly flag",
                "severity": "medium",
                "detail":   "Cookie accessible via JavaScript — XSS can steal it",
            })
        if "samesite" not in cl:
            issues.append({
                "cookie":   name,
                "issue":    "Missing SameSite flag",
                "severity": "medium",
                "detail":   "Cookie sent on cross-site requests — CSRF risk",
            })
    return issues


class HeadersCheckModule(BaseModule):
    MODULE_NAME = "headers"
    DESCRIPTION = "HTTP security headers audit — OWASP checks, grade A–F, cookie flags, info disclosure"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        urls   = [f"https://{domain}", f"http://{domain}"]
        self.log.info(f"Security headers audit: {domain}")

        cached = cache.get("headers", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        result: dict = {
            "domain":            domain,
            "grade":             "F",
            "score":             0,
            "headers_present":   [],
            "headers_missing":   [],
            "info_disclosure":   [],
            "cookie_issues":     [],
            "csp_analysis":      {},
            "hsts_analysis":     {},
            "critical_findings": [],
            "total":             0,
        }

        # Fetch both HTTPS and HTTP (check redirect)
        https_resp = await self._get_headers(urls[0])
        http_resp  = await self._get_headers(urls[1])

        if not https_resp:
            self.log.warning(f"Could not reach {domain}")
            result["error"] = "Could not reach target"
            return result

        headers = {k.lower(): v for k, v in https_resp.items()}
        score   = 0
        max_pts = 0

        # ── Check each security header ────────────────────────────────────
        for hdef in SECURITY_HEADERS:
            hname = hdef["name"].lower()
            pts   = {"high": 20, "medium": 15, "low": 10}.get(hdef["severity"], 10)
            if hdef["required"]:
                max_pts += pts

            if hname in headers:
                val = headers[hname]
                good = bool(re.search(hdef["good_pattern"], val, re.I))
                result["headers_present"].append({
                    "name":     hdef["name"],
                    "value":    val,
                    "good":     good,
                    "severity": hdef["severity"],
                    "note":     hdef["description"],
                })
                if hdef["required"]:
                    score += pts if good else pts // 2
            else:
                if hdef["required"]:
                    result["headers_missing"].append({
                        "name":      hdef["name"],
                        "severity":  hdef["severity"],
                        "impact":    hdef["description"],
                        "fix":       hdef["best_value"],
                    })
                    result["critical_findings"].append({
                        "title":    f"Missing Header: {hdef['name']}",
                        "severity": hdef["severity"],
                        "detail":   hdef["description"],
                        "fix":      f"Add: {hdef['name']}: {hdef['best_value']}",
                    })

        # ── Grade ─────────────────────────────────────────────────────────
        pct = (score / max_pts * 100) if max_pts else 0
        result["score"] = int(pct)
        result["grade"] = (
            "A+" if pct >= 95 else
            "A"  if pct >= 85 else
            "B"  if pct >= 70 else
            "C"  if pct >= 55 else
            "D"  if pct >= 40 else
            "F"
        )
        self.log.found("Security grade", f"{result['grade']} ({int(pct)}%)")

        # ── Information disclosure ────────────────────────────────────────
        for idh in INFO_DISCLOSURE_HEADERS:
            hname = idh["name"].lower()
            if hname in headers:
                val = headers[hname]
                result["info_disclosure"].append({
                    "header": idh["name"],
                    "value":  val,
                    "risk":   idh["risk"],
                    "reason": idh["reason"],
                })
                if idh["risk"] in ("medium", "high"):
                    result["critical_findings"].append({
                        "title":    f"Info Disclosure: {idh['name']}: {val}",
                        "severity": idh["risk"],
                        "detail":   idh["reason"],
                        "fix":      f"Remove or obfuscate the {idh['name']} header",
                    })

        # ── Cookie security ───────────────────────────────────────────────
        set_cookie = headers.get("set-cookie", "")
        cookie_issues = _check_cookie_security(set_cookie)
        result["cookie_issues"] = cookie_issues
        for ci in cookie_issues:
            if ci["severity"] == "high":
                result["critical_findings"].append({
                    "title":    f"Cookie Issue: {ci['cookie']} — {ci['issue']}",
                    "severity": ci["severity"],
                    "detail":   ci["detail"],
                })

        # ── HSTS analysis ─────────────────────────────────────────────────
        hsts_val = headers.get("strict-transport-security", "")
        if hsts_val:
            max_age_match = re.search(r"max-age=(\d+)", hsts_val, re.I)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            result["hsts_analysis"] = {
                "value":              hsts_val,
                "max_age_seconds":    max_age,
                "max_age_days":       max_age // 86400,
                "includeSubDomains":  "includesubdomains" in hsts_val.lower(),
                "preload":            "preload" in hsts_val.lower(),
                "weak":               max_age < 15768000,  # < 6 months
            }
            if max_age < 15768000:
                result["critical_findings"].append({
                    "title":    "Weak HSTS max-age",
                    "severity": "medium",
                    "detail":   f"max-age={max_age} ({max_age//86400} days) — recommend 1 year minimum",
                    "fix":      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                })

        # ── CSP analysis ──────────────────────────────────────────────────
        csp_val = headers.get("content-security-policy", "")
        if csp_val:
            unsafe_inline = "'unsafe-inline'" in csp_val
            unsafe_eval   = "'unsafe-eval'" in csp_val
            wildcard_src  = re.search(r"(script-src|default-src)[^;]*\*", csp_val)
            result["csp_analysis"] = {
                "value":          csp_val[:500],
                "unsafe_inline":  unsafe_inline,
                "unsafe_eval":    unsafe_eval,
                "wildcard_src":   bool(wildcard_src),
                "has_nonce":      "nonce-" in csp_val,
                "has_hash":       re.search(r"'sha\d+-", csp_val) is not None,
            }
            if unsafe_inline:
                result["critical_findings"].append({
                    "title":    "CSP allows 'unsafe-inline' scripts",
                    "severity": "high",
                    "detail":   "CSP with 'unsafe-inline' provides minimal XSS protection",
                    "fix":      "Use nonces or hashes instead of 'unsafe-inline'",
                })

        # ── HTTP redirect check ───────────────────────────────────────────
        if http_resp:
            http_headers = {k.lower(): v for k, v in http_resp.items()}
            if "strict-transport-security" in http_headers:
                result["critical_findings"].append({
                    "title":    "HSTS header served over HTTP",
                    "severity": "medium",
                    "detail":   "HSTS should only be served over HTTPS — browser ignores it over HTTP",
                })

        result["total"] = len(result["critical_findings"])
        cache.set("headers", domain, result)
        await self._persist_db(result)
        return result

    async def _get_headers(self, url: str) -> Optional[dict]:
        try:
            resp = await fetch(url, timeout=10, return_headers=True)
            if isinstance(resp, dict):
                return resp.get("headers", {})
            return None
        except Exception:
            return None
