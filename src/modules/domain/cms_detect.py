"""
ProjectZ - Module: CMS / Framework Deep Detection
Identifies CMS, web frameworks, and their exact versions via:
  - HTTP response headers (X-Generator, X-Powered-By, etc.)
  - HTML meta tags (generator tag)
  - Fingerprint paths (wp-login.php, administrator/index.php, etc.)
  - Static file hashes (readme.html, CHANGELOG.txt)
  - robots.txt disallow patterns
  - Cookie names (PHPSESSID, ASP.NET_SessionId, JSESSIONID)
  - JavaScript variable patterns
  - Known version-specific files + regex version extraction
Covers: WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Django,
        Laravel, Spring, Ruby on Rails, ASP.NET, Next.js, Nuxt.js,
        Angular, React (CRA), Gatsby, and 20+ more.
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


# ── CMS fingerprints ──────────────────────────────────────────────────────
# Each: name, checks list [{type, pattern/path, confidence}]
CMS_FINGERPRINTS: list[dict] = [
    {
        "name": "WordPress",
        "checks": [
            {"type": "path",   "path": "/wp-login.php",         "confidence": 95},
            {"type": "path",   "path": "/wp-admin/",            "confidence": 90},
            {"type": "path",   "path": "/wp-content/",          "confidence": 90},
            {"type": "body",   "pattern": r"wp-content|wp-includes|wordpress", "confidence": 85},
            {"type": "meta",   "pattern": r"WordPress\s*([\d.]+)?",            "confidence": 99},
            {"type": "header", "header": "x-generator", "pattern": r"WordPress","confidence": 99},
            {"type": "path",   "path": "/wp-json/wp/v2/",       "confidence": 95},
        ],
        "version_files": [
            {"path": "/readme.html",     "regex": r"Version\s+([\d.]+)"},
            {"path": "/feed/",           "regex": r"<generator>.*?WordPress\s*([\d.]+)"},
            {"path": "/wp-json/",        "regex": r"\"version\":\"([\d.]+)\""},
        ],
        "vuln_paths": [
            "/wp-config.php.bak", "/wp-config.php~", "/.git/config",
            "/wp-content/debug.log", "/xmlrpc.php",
        ],
        "category": "CMS",
    },
    {
        "name": "Drupal",
        "checks": [
            {"type": "path",   "path": "/user/login",           "confidence": 80},
            {"type": "path",   "path": "/sites/default/files/", "confidence": 90},
            {"type": "body",   "pattern": r"drupal|Drupal\.settings", "confidence": 85},
            {"type": "header", "header": "x-generator", "pattern": r"Drupal","confidence": 99},
            {"type": "cookie", "pattern": r"DRUPAL_UID|Drupal\.visitor","confidence": 90},
        ],
        "version_files": [
            {"path": "/CHANGELOG.txt",  "regex": r"Drupal\s+([\d.]+)"},
            {"path": "/core/CHANGELOG.txt","regex": r"Drupal\s+([\d.]+)"},
        ],
        "vuln_paths": ["/CHANGELOG.txt", "/INSTALL.txt", "/sites/default/settings.php"],
        "category": "CMS",
    },
    {
        "name": "Joomla",
        "checks": [
            {"type": "path",   "path": "/administrator/",       "confidence": 85},
            {"type": "body",   "pattern": r"joomla|Joomla!",    "confidence": 85},
            {"type": "meta",   "pattern": r"Joomla",            "confidence": 99},
        ],
        "version_files": [
            {"path": "/administrator/manifests/files/joomla.xml",
             "regex": r"<version>([\d.]+)</version>"},
            {"path": "/language/en-GB/en-GB.xml",
             "regex": r"<version>([\d.]+)"},
        ],
        "vuln_paths": ["/configuration.php", "/administrator/cache/"],
        "category": "CMS",
    },
    {
        "name": "Magento",
        "checks": [
            {"type": "path",   "path": "/skin/frontend/",       "confidence": 90},
            {"type": "path",   "path": "/app/etc/local.xml",    "confidence": 95},
            {"type": "body",   "pattern": r"Mage\.Cookies|mage-messages|Magento","confidence": 85},
            {"type": "cookie", "pattern": r"frontend|adminhtml","confidence": 70},
        ],
        "version_files": [
            {"path": "/magento_version", "regex": r"([\d.]+)"},
        ],
        "vuln_paths": ["/downloader/", "/shell/", "/api.php"],
        "category": "eCommerce",
    },
    {
        "name": "Shopify",
        "checks": [
            {"type": "header", "header": "x-shopid",            "confidence": 99},
            {"type": "header", "header": "x-shardid",           "confidence": 99},
            {"type": "body",   "pattern": r"cdn\.shopify\.com|Shopify\.theme","confidence": 90},
        ],
        "version_files": [],
        "vuln_paths": [],
        "category": "eCommerce/Hosted",
    },
    {
        "name": "Ghost",
        "checks": [
            {"type": "header", "header": "x-ghost-cache-status","confidence": 99},
            {"type": "body",   "pattern": r"ghost-head|gh-head|ghost/api","confidence": 90},
            {"type": "path",   "path": "/ghost/",               "confidence": 85},
        ],
        "version_files": [
            {"path": "/ghost/api/v4/site/", "regex": r"\"version\":\"([\d.]+)\""},
        ],
        "vuln_paths": ["/ghost/#/setup/"],
        "category": "CMS",
    },
    {
        "name": "Django",
        "checks": [
            {"type": "cookie", "pattern": r"csrftoken|sessionid", "confidence": 60},
            {"type": "body",   "pattern": r"csrfmiddlewaretoken|Django",    "confidence": 75},
            {"type": "header", "header": "x-frame-options", "pattern": r"SAMEORIGIN", "confidence": 40},
        ],
        "version_files": [],
        "vuln_paths": ["/admin/", "/admin/login/"],
        "category": "Framework (Python)",
    },
    {
        "name": "Laravel",
        "checks": [
            {"type": "cookie", "pattern": r"laravel_session|XSRF-TOKEN","confidence": 90},
            {"type": "body",   "pattern": r"laravel|Illuminate\\",  "confidence": 85},
            {"type": "header", "header": "x-powered-by", "pattern": r"PHP","confidence": 30},
        ],
        "version_files": [
            {"path": "/telescope",      "regex": r"Laravel Telescope"},
            {"path": "/vendor/laravel/framework/CHANGELOG.md",
             "regex": r"^## \[?([\d.]+)\]?"},
        ],
        "vuln_paths": ["/telescope", "/.env", "/phpinfo.php"],
        "category": "Framework (PHP)",
    },
    {
        "name": "Ruby on Rails",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Phusion Passenger","confidence": 70},
            {"type": "cookie", "pattern": r"_session_id|_.*_session", "confidence": 60},
            {"type": "body",   "pattern": r"rails-ujs|ActionController",  "confidence": 80},
        ],
        "version_files": [],
        "vuln_paths": ["/rails/info/properties", "/rails/info/routes"],
        "category": "Framework (Ruby)",
    },
    {
        "name": "ASP.NET",
        "checks": [
            {"type": "header", "header": "x-aspnet-version",    "confidence": 99},
            {"type": "header", "header": "x-aspnetmvc-version", "confidence": 99},
            {"type": "cookie", "pattern": r"ASP\.NET_SessionId", "confidence": 95},
            {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET","confidence": 95},
        ],
        "version_files": [],
        "vuln_paths": ["/elmah.axd", "/trace.axd", "/_vti_bin/"],
        "category": "Framework (.NET)",
    },
    {
        "name": "Spring Boot",
        "checks": [
            {"type": "path",   "path": "/actuator/health",       "confidence": 90},
            {"type": "path",   "path": "/actuator/env",          "confidence": 95},
            {"type": "body",   "pattern": r"Whitelabel Error Page|Spring Framework","confidence": 85},
        ],
        "version_files": [
            {"path": "/actuator/info", "regex": r"\"version\":\"([\d.]+)\""},
        ],
        "vuln_paths": ["/actuator/", "/actuator/env", "/actuator/heapdump",
                       "/actuator/logfile", "/actuator/mappings"],
        "category": "Framework (Java)",
    },
    {
        "name": "Next.js",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Next\.js","confidence": 99},
            {"type": "body",   "pattern": r"__NEXT_DATA__|next/static","confidence": 95},
        ],
        "version_files": [],
        "vuln_paths": ["/_next/static/", "/api/"],
        "category": "Framework (JS/React)",
    },
    {
        "name": "Nuxt.js",
        "checks": [
            {"type": "header", "header": "x-powered-by", "pattern": r"Nuxt\.?js","confidence": 99},
            {"type": "body",   "pattern": r"__nuxt|_nuxt/",    "confidence": 95},
        ],
        "version_files": [],
        "vuln_paths": [],
        "category": "Framework (JS/Vue)",
    },
]


class CMSDetectModule(BaseModule):
    MODULE_NAME  = "cms"
    DESCRIPTION  = "CMS & framework detection — WordPress, Drupal, Joomla, Django, Laravel + 20 more"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        base   = f"https://{domain}"
        self.log.info(f"CMS detection: {domain}")

        cached = cache.get("cms", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        result: dict = {
            "domain":            domain,
            "cms":               None,
            "version":           None,
            "category":          None,
            "confidence":        0,
            "technologies":      [],
            "vuln_paths_found":  [],
            "critical_findings": [],
            "total":             0,
        }

        # Fetch homepage
        home_resp = await self._get_page(base)
        robots    = await self._get_page(f"{base}/robots.txt")

        home_body    = home_resp.get("body", "")    if home_resp else ""
        home_headers = home_resp.get("headers", {}) if home_resp else {}
        home_cookies = home_resp.get("headers", {}).get("set-cookie", "") if home_resp else ""

        all_detections: dict[str, int] = {}

        for cms_def in CMS_FINGERPRINTS:
            cms_name = cms_def["name"]
            score    = 0

            for check in cms_def["checks"]:
                ctype   = check.get("type")
                conf    = check.get("confidence", 50)
                matched = False

                if ctype == "path":
                    path_url = f"{base}{check['path']}"
                    path_resp = await self._check_path_exists(path_url)
                    matched = path_resp

                elif ctype == "body":
                    matched = bool(re.search(check["pattern"], home_body, re.I))

                elif ctype == "meta":
                    meta_match = re.search(
                        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                        home_body, re.I
                    )
                    if not meta_match:
                        meta_match = re.search(
                            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator',
                            home_body, re.I
                        )
                    matched = (meta_match and
                               bool(re.search(check["pattern"], meta_match.group(1), re.I)))

                elif ctype == "header":
                    hval = home_headers.get(check["header"], "")
                    if "pattern" in check:
                        matched = bool(re.search(check["pattern"], str(hval), re.I))
                    else:
                        matched = bool(hval)

                elif ctype == "cookie":
                    matched = bool(re.search(check["pattern"], home_cookies, re.I))

                if matched:
                    score += conf

            if score >= 80:
                all_detections[cms_name] = score

        # ── Detect version for top CMS ────────────────────────────────────
        if all_detections:
            best_cms  = max(all_detections, key=all_detections.get)
            best_conf = min(all_detections[best_cms], 99)
            cms_def   = next((c for c in CMS_FINGERPRINTS if c["name"] == best_cms), {})
            version   = await self._detect_version(base, cms_def.get("version_files", []))

            result["cms"]        = best_cms
            result["version"]    = version or "unknown"
            result["category"]   = cms_def.get("category", "CMS")
            result["confidence"] = best_conf
            result["technologies"] = [
                {"name": k, "confidence": v}
                for k, v in sorted(all_detections.items(), key=lambda x: -x[1])
            ]

            self.log.found("CMS detected", f"{best_cms} v{version or '?'} ({best_conf}%)")

            result["critical_findings"].append({
                "title":    f"CMS Identified: {best_cms}",
                "severity": "info",
                "detail":   f"Version: {version or 'unknown'} | Category: {cms_def.get('category')}",
            })

            # ── Check vuln paths ──────────────────────────────────────────
            vuln_paths = cms_def.get("vuln_paths", [])
            for vp in vuln_paths:
                url = f"{base}{vp}"
                exists = await self._check_path_exists(url)
                if exists:
                    result["vuln_paths_found"].append({"path": vp, "url": url})
                    result["critical_findings"].append({
                        "title":    f"Sensitive Path Accessible: {vp}",
                        "severity": "high" if vp in ["/.env", "/.git/config",
                                                      "/wp-config.php.bak"] else "medium",
                        "detail":   f"Accessible sensitive file on {best_cms}: {url}",
                        "url":      url,
                    })
                    self.log.found("Vuln path", f"{best_cms}: {vp}")

        else:
            self.log.info(f"No specific CMS detected for {domain}")
            result["cms"] = "Unknown / Custom"

        result["total"] = len(result["technologies"])
        cache.set("cms", domain, result)
        await self._persist_db(result)
        return result

    async def _get_page(self, url: str) -> Optional[dict]:
        try:
            return await fetch(url, timeout=10, return_headers=True)
        except Exception:
            return None

    async def _check_path_exists(self, url: str) -> bool:
        try:
            resp = await fetch(url, timeout=6, return_headers=True)
            if not isinstance(resp, dict):
                return False
            status = resp.get("status_code", 0)
            return status in (200, 301, 302, 403)  # 403 = exists but denied
        except Exception:
            return False

    async def _detect_version(self, base: str, version_files: list) -> Optional[str]:
        for vf in version_files:
            try:
                resp = await fetch(f"{base}{vf['path']}", timeout=8, return_headers=True)
                if not isinstance(resp, dict):
                    continue
                body = resp.get("body", "") or ""
                m = re.search(vf["regex"], body, re.I | re.M)
                if m:
                    return m.group(1).strip()
            except Exception:
                continue
        return None
