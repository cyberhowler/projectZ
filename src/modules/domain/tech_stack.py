from __future__ import annotations
"""
ProjectZ - Module 05: Technology Stack Detection
Wappalyzer-style fingerprinting via HTTP headers, HTML patterns, cookies.
Self-coded — no Wappalyzer API needed.
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


# ── Fingerprint database ──────────────────────────────────────────────────────
# Format: category → { tech_name: [patterns_to_match] }
FINGERPRINTS: dict[str, dict[str, list[str]]] = {
    "CMS": {
        "WordPress":   ["wp-content", "wp-includes", "wordpress", "/wp-json/"],
        "Joomla":      ["joomla", "/components/com_", "Joomla!"],
        "Drupal":      ["drupal", "Drupal.settings", "sites/default/files"],
        "Shopify":     ["shopify", "cdn.shopify.com", "Shopify.theme"],
        "Magento":     ["Mage.Cookies", "magento", "/skin/frontend/"],
        "Ghost":       ["ghost.io", "ghost/api"],
        "Wix":         ["wix.com", "_wixCIDX", "X-Wix-"],
        "Squarespace": ["squarespace.com", "static.squarespace.com"],
        "Webflow":     ["webflow.com", "Webflow:"],
    },
    "Framework": {
        "React":          ["react.js", "react.min.js", "__REACT_DEVTOOLS", "data-reactroot"],
        "Vue.js":         ["vue.js", "vue.min.js", "__vue__", "data-v-"],
        "Angular":        ["angular.js", "ng-version=", "angular.min.js"],
        "Next.js":        ["__NEXT_DATA__", "_next/static"],
        "Nuxt.js":        ["__nuxt", "_nuxt/"],
        "Django":         ["csrfmiddlewaretoken", "django", "__admin_media_prefix__"],
        "Laravel":        ["laravel_session", "Laravel"],
        "Ruby on Rails":  ["X-Runtime", "_rails_", "rails.js"],
        "Express.js":     ["X-Powered-By: Express"],
        "FastAPI":        ["fastapi", "swagger-ui"],
        "Spring":         ["X-Application-Context", "spring"],
    },
    "Server": {
        "Apache":   ["Apache/", "Server: Apache"],
        "Nginx":    ["nginx/", "Server: nginx"],
        "IIS":      ["Microsoft-IIS", "Server: IIS"],
        "Cloudflare": ["cloudflare", "cf-ray", "Server: cloudflare"],
        "Caddy":    ["Server: Caddy"],
        "LiteSpeed":["Server: LiteSpeed"],
        "Gunicorn": ["gunicorn", "Server: gunicorn"],
    },
    "CDN": {
        "Cloudflare":   ["cf-cache-status", "cf-ray"],
        "Fastly":       ["X-Served-By: cache", "Fastly"],
        "Akamai":       ["X-Akamai", "akamai"],
        "AWS CloudFront": ["X-Amz-Cf-Id", "cloudfront.net"],
        "jsDelivr":     ["jsdelivr.net"],
        "Unpkg":        ["unpkg.com"],
    },
    "Analytics": {
        "Google Analytics":    ["google-analytics.com/analytics.js", "gtag(", "UA-", "G-"],
        "Google Tag Manager":  ["googletagmanager.com/gtm.js", "GTM-"],
        "Hotjar":              ["hotjar.com", "hj.q"],
        "Mixpanel":            ["mixpanel.com/lib"],
        "Segment":             ["segment.com/analytics.js"],
        "Matomo":              ["matomo.js", "piwik.js"],
    },
    "Database": {
        "MySQL":      ["mysql_error", "MySQL server"],
        "PostgreSQL": ["PostgreSQL", "PG::"],
        "MongoDB":    ["MongoDB", "mongoError"],
        "Redis":      ["redis", "REDIS"],
        "Elasticsearch": ["elasticsearch", "index.html#/"],
    },
    "Security": {
        "Cloudflare WAF": ["__cfduid", "cf-ray"],
        "reCAPTCHA":      ["recaptcha", "google.com/recaptcha"],
        "hCaptcha":       ["hcaptcha.com"],
        "HSTS":           ["Strict-Transport-Security"],
        "CSP":            ["Content-Security-Policy"],
    },
    "JavaScript": {
        "jQuery":      ["jquery.js", "jquery.min.js", "jQuery v"],
        "Bootstrap":   ["bootstrap.css", "bootstrap.min.js"],
        "Tailwind":    ["tailwindcss", "tailwind.config"],
        "Lodash":      ["lodash.js", "lodash.min.js"],
        "Axios":       ["axios.min.js", "axios/lib"],
        "Three.js":    ["three.js", "THREE.WebGLRenderer"],
    },
    "Hosting": {
        "Vercel":     ["x-vercel-id", "vercel.app"],
        "Netlify":    ["x-nf-request-id", "netlify.app"],
        "Heroku":     ["herokuapp.com", "X-Heroku"],
        "AWS":        ["amazonaws.com", "x-amz-request-id"],
        "GCP":        ["X-GFE-Response-Code-Details", "appspot.com"],
        "Azure":      ["x-ms-request-id", "azurewebsites.net"],
        "GitHub Pages": ["github.io"],
    },
}


class TechStackModule(BaseModule):
    MODULE_NAME = "tech"
    DESCRIPTION = "Technology fingerprinting — CMS, framework, server, CDN, analytics"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Tech stack detection: {domain}")

        cached = cache.get("tech", domain)
        if cached:
            return cached

        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                data = await self._fetch(url)
                if data:
                    break
            except Exception:
                data = None

        if not data:
            return {"domain": domain, "error": "Could not reach target", "technologies": {}}

        detected = self._fingerprint(data)
        result   = self._build_result(domain, detected, data)

        cache.set("tech", domain, result)
        await self._persist_db(result)
        return result

    async def _fetch(self, url: str) -> Optional[dict]:
        timeout = aiohttp.ClientTimeout(total=self.options.get("timeout", 12))
        try:
            _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
            body    = _r["text"]
            headers = dict(_r["headers"])
            cookies = {}  # fetch() dict response has no cookies object
            return {
                "body":    body[:200_000],   # cap at 200 KB
                "headers": headers,
                "cookies": cookies,
                "status":  _r["status"],
                "url":     str(_r["url"]),
                "final_url": str(_r["url"]),
            }
        except Exception as e:
            self.log.warning(f"Fetch failed {url}: {e}")
            return None

    def _fingerprint(self, data: dict) -> dict[str, list[str]]:
        """Match all fingerprint patterns against body + headers + cookies."""
        body    = data.get("body", "").lower()
        headers = " ".join(f"{k}: {v}" for k, v in data.get("headers", {}).items()).lower()
        cookies = " ".join(data.get("cookies", {}).keys()).lower()
        haystack = f"{body} {headers} {cookies}"

        detected: dict[str, list[str]] = {}
        for category, techs in FINGERPRINTS.items():
            for tech, patterns in techs.items():
                if any(p.lower() in haystack for p in patterns):
                    detected.setdefault(category, []).append(tech)

        return detected

    def _build_result(self, domain: str, detected: dict, data: dict) -> dict:
        flat_list = [t for techs in detected.values() for t in techs]
        headers   = data.get("headers", {})

        result = {
            "domain":       domain,
            "total":       1,
            "technologies": detected,
            "tech_list":    flat_list,
            "total_found":  len(flat_list),
            "server":       headers.get("Server", headers.get("server", "")),
            "powered_by":   headers.get("X-Powered-By", headers.get("x-powered-by", "")),
            "cms":          detected.get("CMS", []),
            "frameworks":   detected.get("Framework", []),
            "cdn":          detected.get("CDN", []),
            "analytics":    detected.get("Analytics", []),
            "security_headers": {
                "hsts":  "Strict-Transport-Security" in headers,
                "csp":   "Content-Security-Policy" in headers,
                "xfo":   "X-Frame-Options" in headers,
                "xcto":  "X-Content-Type-Options" in headers,
                "xss":   "X-XSS-Protection" in headers,
            },
            "http_status": data.get("status"),
            "final_url":   data.get("final_url"),
        }

        for tech in flat_list:
            self.log.found("Technology", tech)

        return result


    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
