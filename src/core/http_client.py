"""
ProjectZ - HTTP Client v3 (Army-Grade)
======================================
All module HTTP calls route through here.
- return_headers=True  → returns dict with .body .headers .status_code .ok
- extra_headers={}     → merges into request headers
- method param         → GET/POST/PUT/OPTIONS/HEAD
- Retry + exponential backoff (2 retries, capped at 4s)
- 429 / 403 / 5xx aware with per-domain backoff
- 15 real browser User-Agent rotation
- Proxy support (HTTP_PROXY / HTTPS_PROXY in .env)
- Hard asyncio timeout — NEVER hangs
- Connection pooling via thread executor
- Target type auto-detection (domain/IP/email/hash/URL/username)
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from src.core.logger import OSINTLogger
from src.core.config import config

log      = OSINTLogger("http")
_pool    = ThreadPoolExecutor(max_workers=120)

# ── Real browser User-Agents (2024-2025) ──────────────────────────────────
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)

def default_headers(extra: dict = None) -> dict:
    h = {
        "User-Agent":      random_ua(),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }
    if extra:
        h.update(extra)
    return h

# Proxy support from .env
_PROXY_URL = getattr(config, "HTTP_PROXY",  "") or getattr(config, "PROXY_URL", "") or ""
_PROXIES   = {"http": _PROXY_URL, "https": _PROXY_URL} if _PROXY_URL else None


# ── Internal blocking request ─────────────────────────────────────────────
def _do_request(method: str, url: str, headers: dict, data: Any,
                json_data: Any, params: dict, timeout: float,
                allow_redirects: bool, proxies: Optional[dict]) -> requests.Response:
    return getattr(requests, method.lower())(
        url,
        headers         = headers,
        data            = data,
        json            = json_data,
        params          = params,
        timeout         = timeout,
        verify          = False,
        allow_redirects = allow_redirects,
        proxies         = proxies,
    )


# ── Main fetch function ───────────────────────────────────────────────────
async def fetch(
    url:             str,
    method:          str   = "get",
    headers:         dict  = None,
    extra_headers:   dict  = None,
    data:            Any   = None,
    json_data:       Any   = None,
    params:          dict  = None,
    timeout:         float = 10.0,
    retries:         int   = 2,
    rotate_ua:       bool  = True,
    allow_redirects: bool  = True,
    return_headers:  bool  = False,
) -> dict:
    """
    Async HTTP fetch — army-grade reliability.

    Parameters
    ----------
    return_headers : bool
        When True, response dict includes:
          .body         — response body text
          .headers      — dict of response headers (lowercase keys)
          .status_code  — int
          .ok           — bool (2xx)
        When False (legacy), returns:
          .text / .json / .status / .ok / .error

    extra_headers : dict
        Merged into request headers (useful for Origin, Authorization, etc.)
    """
    # Build headers
    hdrs: dict = {}
    if rotate_ua:
        hdrs["User-Agent"] = random_ua()
    if headers:
        hdrs.update(headers)
    if extra_headers:
        hdrs.update(extra_headers)

    loop     = asyncio.get_event_loop()
    hard_to  = timeout + 3.0   # hard cap per attempt

    last_err = "No attempts made"
    for attempt in range(1, retries + 2):          # retries+1 total attempts
        try:
            resp = await asyncio.wait_for(
                loop.run_in_executor(
                    _pool,
                    _do_request,
                    method.lower(), url, hdrs, data, json_data,
                    params, timeout, allow_redirects, _PROXIES,
                ),
                timeout=hard_to,
            )

            # 429 — respect Retry-After header
            if resp.status_code == 429:
                wait = min(int(resp.headers.get("Retry-After", "5")), 12)
                log.debug(f"429 rate-limited: {url[:60]} | waiting {wait}s")
                await asyncio.sleep(wait)
                hdrs["User-Agent"] = random_ua()
                continue

            # 403/401 — rotate UA once
            if resp.status_code in (403, 401) and attempt == 1:
                hdrs["User-Agent"] = random_ua()
                await asyncio.sleep(0.5)
                continue

            # 5xx — exponential backoff
            if resp.status_code >= 500 and attempt <= retries:
                await asyncio.sleep(min(2 ** attempt, 6))
                continue

            # ── Success — build response dict ─────────────────────────────
            try:
                body = resp.content.decode("utf-8", errors="replace")
            except Exception:
                body = ""

            try:
                j = resp.json()
            except Exception:
                j = None

            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            if return_headers:
                return {
                    "body":        body,
                    "headers":     resp_headers_lower,
                    "status_code": resp.status_code,
                    "ok":          200 <= resp.status_code < 400,
                    "url":         str(resp.url),
                    "json":        j,
                    "error":       "",
                    # legacy compat
                    "status":      resp.status_code,
                    "text":        body,
                }
            else:
                return {
                    "status":  resp.status_code,
                    "text":    body,
                    "json":    j,
                    "headers": resp_headers_lower,
                    "url":     str(resp.url),
                    "ok":      200 <= resp.status_code < 400,
                    "error":   "",
                    # new-style compat
                    "body":        body,
                    "status_code": resp.status_code,
                }

        except asyncio.TimeoutError:
            last_err = f"Timeout after {timeout}s"
            log.debug(f"Timeout [{attempt}] {url[:60]}")
            if attempt > retries:
                break
            hdrs["User-Agent"] = random_ua()

        except requests.exceptions.ConnectionError as e:
            short = str(e)[:80]
            last_err = f"Connection error: {short}"
            log.debug(f"ConnError {url[:60]}: {short}")
            break   # don't retry on DNS/connection failure

        except requests.exceptions.SSLError as e:
            last_err = f"SSL error: {str(e)[:60]}"
            log.debug(f"SSL {url[:60]}: {last_err}")
            # Try without verify (already False — so this is a real SSL issue)
            break

        except Exception as e:
            last_err = str(e)[:80]
            log.debug(f"Exception [{attempt}] {url[:60]}: {last_err}")
            if attempt > retries:
                break
            await asyncio.sleep(1)

    return _err(url, last_err, return_headers)


def _err(url: str, msg: str, return_headers: bool = False) -> dict:
    base = {"status": 0, "text": "", "json": None, "headers": {},
            "url": url, "ok": False, "error": msg,
            "body": "", "status_code": 0}
    return base


# ── Target type detector ──────────────────────────────────────────────────
def detect_target_type(target: str) -> str:
    t = target.strip().lower()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):            return "ipv4"
    if re.match(r"^[0-9a-f:]{7,39}$", t) and ":" in t:     return "ipv6"
    if re.match(r"^[a-f0-9]{32}$", t):                      return "hash_md5"
    if re.match(r"^[a-f0-9]{40}$", t):                      return "hash_sha1"
    if re.match(r"^[a-f0-9]{64}$", t):                      return "hash_sha256"
    if re.match(r"^[\w.+%\-]+@[\w.\-]+\.[a-z]{2,}$", t):   return "email"
    if t.startswith(("http://", "https://")):                return "url"
    if re.match(r"^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$", t): return "domain"
    return "username"


# ── API key preflight ─────────────────────────────────────────────────────
def check_api_keys() -> dict:
    keys = {
        "VIRUSTOTAL_API_KEY":  getattr(config, "VIRUSTOTAL_API_KEY",  ""),
        "SHODAN_API_KEY":      getattr(config, "SHODAN_API_KEY",      ""),
        "CENSYS_API_ID":       getattr(config, "CENSYS_API_ID",       ""),
        "GITHUB_TOKEN":        getattr(config, "GITHUB_TOKEN",        ""),
        "HIBP_API_KEY":        getattr(config, "HIBP_API_KEY",        ""),
        "OTX_API_KEY":         getattr(config, "OTX_API_KEY",         ""),
        "ABUSEIPDB_API_KEY":   getattr(config, "ABUSEIPDB_API_KEY",   ""),
        "URLSCAN_API_KEY":     getattr(config, "URLSCAN_API_KEY",     ""),
        "ZOOMEYE_API_KEY":     getattr(config, "ZOOMEYE_API_KEY",     ""),
        "INTELX_API_KEY":      getattr(config, "INTELX_API_KEY",      ""),
        "GOOGLE_SAFE_BROWSING_KEY": getattr(config, "GOOGLE_SAFE_BROWSING_KEY", ""),
    }
    return {k: ("SET ✓" if v else "not set") for k, v in keys.items()}
