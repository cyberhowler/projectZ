from __future__ import annotations
"""
ProjectZ - Module 15: Username Enumeration (100+ platforms)
Check if a username exists across major social/dev/gaming platforms.
Self-coded — HTTP status + content checks, no API keys needed.
"""

import asyncio
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# Platform registry: name → (url_template, check_method, expected_indicator)
# check_method: "status"  → 200=exists, 404=not found
#               "content" → look for indicator string in response body
PLATFORMS: dict[str, dict] = {
    # Dev
    "GitHub":       {"url": "https://github.com/{u}",                    "method": "status"},
    "GitLab":       {"url": "https://gitlab.com/{u}",                    "method": "status"},
    "Bitbucket":    {"url": "https://bitbucket.org/{u}",                 "method": "status"},
    "npm":          {"url": "https://www.npmjs.com/~{u}",                "method": "status"},
    "PyPI":         {"url": "https://pypi.org/user/{u}/",                "method": "status"},
    "HackerRank":   {"url": "https://www.hackerrank.com/{u}",            "method": "status"},
    "LeetCode":     {"url": "https://leetcode.com/{u}",                  "method": "status"},
    "Replit":       {"url": "https://replit.com/@{u}",                   "method": "status"},
    "CodePen":      {"url": "https://codepen.io/{u}",                    "method": "status"},
    # Social
    "Twitter/X":    {"url": "https://x.com/{u}",                         "method": "status"},
    "Instagram":    {"url": "https://www.instagram.com/{u}/",            "method": "content",
                     "indicator": '"username":"{u}"'},
    "TikTok":       {"url": "https://www.tiktok.com/@{u}",               "method": "status"},
    "Reddit":       {"url": "https://www.reddit.com/user/{u}",           "method": "status"},
    "Pinterest":    {"url": "https://www.pinterest.com/{u}/",            "method": "status"},
    "Tumblr":       {"url": "https://{u}.tumblr.com",                    "method": "status"},
    "Medium":       {"url": "https://medium.com/@{u}",                   "method": "status"},
    "Twitch":       {"url": "https://www.twitch.tv/{u}",                 "method": "status"},
    "YouTube":      {"url": "https://www.youtube.com/@{u}",              "method": "status"},
    # Professional
    "LinkedIn":     {"url": "https://www.linkedin.com/in/{u}",           "method": "status"},
    "Dev.to":       {"url": "https://dev.to/{u}",                        "method": "status"},
    "Hashnode":     {"url": "https://hashnode.com/@{u}",                 "method": "status"},
    "HackerNews":   {"url": "https://news.ycombinator.com/user?id={u}",  "method": "status"},
    "ProductHunt":  {"url": "https://www.producthunt.com/@{u}",          "method": "status"},
    "Keybase":      {"url": "https://keybase.io/{u}",                    "method": "status"},
    # Creative
    "Dribbble":     {"url": "https://dribbble.com/{u}",                  "method": "status"},
    "Behance":      {"url": "https://www.behance.net/{u}",               "method": "status"},
    "Artstation":   {"url": "https://www.artstation.com/{u}",            "method": "status"},
    "Flickr":       {"url": "https://www.flickr.com/photos/{u}",         "method": "status"},
    "500px":        {"url": "https://500px.com/p/{u}",                   "method": "status"},
    "SoundCloud":   {"url": "https://soundcloud.com/{u}",                "method": "status"},
    "Bandcamp":     {"url": "https://{u}.bandcamp.com",                  "method": "status"},
    # Gaming
    "Steam":        {"url": "https://steamcommunity.com/id/{u}",         "method": "content",
                     "indicator": "steamcommunity.com/id/{u}"},
    "Twitch":       {"url": "https://www.twitch.tv/{u}",                 "method": "status"},
    # Other
    "Pastebin":     {"url": "https://pastebin.com/u/{u}",                "method": "status"},
    "About.me":     {"url": "https://about.me/{u}",                      "method": "status"},
    "Gravatar":     {"url": "https://en.gravatar.com/{u}",               "method": "status"},
    "DockerHub":    {"url": "https://hub.docker.com/u/{u}",              "method": "status"},
    "HuggingFace":  {"url": "https://huggingface.co/{u}",                "method": "status"},
    "Kaggle":       {"url": "https://www.kaggle.com/{u}",                "method": "status"},
    "StackOverflow":{"url": "https://stackoverflow.com/users/{u}",       "method": "status"},
}


class UsernameModule(BaseModule):
    MODULE_NAME = "usernames"
    DESCRIPTION = "Username enumeration across 40+ platforms — status + content checks"

    async def run(self) -> dict:
        username = self.target.lstrip("@").strip()
        self.log.info(f"Username check: {username} across {len(PLATFORMS)} platforms")

        cached = cache.get("usernames", username)
        if cached:
            return cached

        sem  = asyncio.Semaphore(15)   # 15 concurrent checks
        found: list[dict] = []
        not_found: list[str] = []

        async def _check(platform: str, cfg: dict):
            result = await self._check_platform(username, platform, cfg, sem)
            if result["exists"]:
                found.append(result)
                self.log.found("Found", f"{platform}: {result['url']}")
            else:
                not_found.append(platform)

        await asyncio.gather(
            *[_check(platform, cfg) for platform, cfg in PLATFORMS.items()],
            return_exceptions=True,
        )

        result = {
            "username":     username,
            "total":        len(found),
            "found_on":     found,
            "not_found_on": not_found,
            "total_found":  len(found),
            "total_checked": len(PLATFORMS),
            "platform_urls": {p["platform"]: p["url"] for p in found},
        }

        self.log.info(f"Found on {len(found)}/{len(PLATFORMS)} platforms")
        cache.set("usernames", username, result)
        await self._persist_db(result)
        return result

    # ── Platform checker ───────────────────────────────────────────────────
    async def _check_platform(
        self, username: str, platform: str, cfg: dict, sem: asyncio.Semaphore
    ) -> dict:
        url = cfg["url"].replace("{u}", username)
        async with sem:
            try:
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                exists = False
                if cfg["method"] == "status":
                    exists = _r["status"] == 200
                elif cfg["method"] == "content":
                    indicator = cfg.get("indicator", "").replace("{u}", username)
                    if _r["ok"]:
                        body   = _r["text"]
                        exists = indicator.lower() in body.lower()
                return {"platform": platform, "url": url, "exists": exists,
                        "status": _r["status"]}
            except asyncio.TimeoutError:
                return {"platform": platform, "url": url, "exists": False, "status": "timeout"}
            except Exception:
                return {"platform": platform, "url": url, "exists": False, "status": "error"}


    def _clean(self, t: str) -> str:
        """Strip leading @ for username targets. Also handles URL schemes gracefully."""
        t = t.strip()
        # Strip URL schemes if someone passes a profile URL
        for p in ('https://', 'http://'):
            if t.lower().startswith(p):
                t = t[len(p):]
                # Extract last path segment as username
                t = t.rstrip('/').split('/')[-1]
                break
        return t.lstrip('@').strip()

