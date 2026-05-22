"""
ProjectZ - Configuration (python-dotenv, no external API keys required)
"""

import os
import re
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
_root = Path(__file__).resolve().parents[2]
load_dotenv(_root / ".env", override=False)

def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


class _Config:
    # ── Optional API keys ─────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY      = _env("VIRUSTOTAL_API_KEY")
    SHODAN_API_KEY          = _env("SHODAN_API_KEY")
    CENSYS_API_ID           = _env("CENSYS_API_ID")
    CENSYS_API_SECRET       = _env("CENSYS_API_SECRET")
    GITHUB_TOKEN            = _env("GITHUB_TOKEN")
    HIBP_API_KEY            = _env("HIBP_API_KEY")
    URLSCAN_API_KEY         = _env("URLSCAN_API_KEY")
    OTX_API_KEY             = _env("OTX_API_KEY")
    ABUSEIPDB_API_KEY       = _env("ABUSEIPDB_API_KEY")
    CERTSPOTTER_API_KEY     = _env("CERTSPOTTER_API_KEY")
    VIRUSTOTAL_API_KEY      = _env("VIRUSTOTAL_API_KEY")
    PHISHTANK_API_KEY       = _env("PHISHTANK_API_KEY")
    GOOGLE_SAFE_BROWSING_KEY= _env("GOOGLE_SAFE_BROWSING_KEY")

    # ── Defaults ──────────────────────────────────────────────────────────
    REQUEST_TIMEOUT    = int(_env("REQUEST_TIMEOUT", "15"))
    MAX_CONCURRENT     = int(_env("MAX_CONCURRENT", "20"))
    CACHE_TTL_HOURS    = int(_env("CACHE_TTL_HOURS", "24"))
    OUTPUT_DIR         = _env("OUTPUT_DIR", "data/results")
    DB_PATH            = _env("DB_PATH", "data/db/projectz.db")
    USER_AGENT         = _env("USER_AGENT",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36")

    DEFAULT_HEADERS = {
        "User-Agent":      USER_AGENT,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }


config = _Config()
