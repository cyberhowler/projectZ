"""
ProjectZ - Module 12: GitHub Intelligence
Organisation members, repos, commit emails, forks, secret scanning hints.
Uses FREE GitHub API (5000 req/h with token, 60/h without).
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config


class GitHubModule(BaseModule):
    MODULE_NAME = "github"
    DESCRIPTION = "GitHub intelligence — org members, repos, commit emails, secrets hints"

    async def run(self) -> dict:
        target  = self._clean(self.target)
        is_user = self.options.get("github_user", False)
        self.log.info(f"GitHub OSINT: {target}")

        cached = cache.get("github", target)
        if cached:
            return cached

        headers = {**config.DEFAULT_HEADERS, "Accept": "application/vnd.github.v3+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"
        else:
            self.log.warning("No GITHUB_TOKEN — rate limited to 60 req/h")

        # Try as org first, then as user
        org_data, user_data = await asyncio.gather(
            self._get_org(target, headers),
            self._get_user(target, headers),
            return_exceptions=True,
        )

        if isinstance(org_data,  Exception): org_data  = {}
        if isinstance(user_data, Exception): user_data = {}

        entity    = org_data or user_data
        entity_type = "org" if org_data else ("user" if user_data else "unknown")

        if not entity:
            # Search by domain
            entity = await self._search_by_domain(target, headers)
            entity_type = "search"

        # Get repos
        entity_name = entity.get("login", target)
        repos       = await self._get_repos(entity_name, entity_type, headers)

        # Get members (org only)
        members     = await self._get_members(entity_name, headers) if org_data else []

        # Extract emails from recent commits
        commit_emails = await self._harvest_commit_emails(repos[:10], headers)

        # Secret patterns in repo names / descriptions
        interesting_repos = self._flag_interesting_repos(repos)

        result = {
            "target":             target,
            "total":              entity.get("public_repos", 0),
            "entity_type":        entity_type,
            "github_url":         entity.get("html_url", ""),
            "name":               entity.get("name", entity.get("login", "")),
            "bio":                entity.get("bio", entity.get("description", "")),
            "location":           entity.get("location", ""),
            "email":              entity.get("email", ""),
            "blog":               entity.get("blog", ""),
            "public_repos":       entity.get("public_repos", 0),
            "followers":          entity.get("followers", 0),
            "following":          entity.get("following", 0),
            "created_at":         entity.get("created_at", ""),
            "repos":              [r.get("full_name", "") for r in repos[:20]],
            "total_repos":        len(repos),
            "members":            members[:30],
            "member_count":       len(members),
            "commit_emails":      sorted(commit_emails),
            "interesting_repos":  interesting_repos,
            "topics":             self._collect_topics(repos),
            "languages":          self._collect_languages(repos),
        }

        self._log_findings(result)

        # Store emails
        for email in commit_emails:
            await DatabaseManager.insert_email(email, target, "github_commits")

        cache.set("github", target, result)
        return result

    # ── Org profile ────────────────────────────────────────────────────────
    async def _get_org(self, name: str, headers: dict) -> dict:
        url = f"https://api.github.com/orgs/{name}"
        return await self._gh_get(url, headers)

    # ── User profile ───────────────────────────────────────────────────────
    async def _get_user(self, name: str, headers: dict) -> dict:
        url = f"https://api.github.com/users/{name}"
        return await self._gh_get(url, headers)

    # ── Repos ──────────────────────────────────────────────────────────────
    async def _get_repos(self, name: str, entity_type: str, headers: dict) -> list[dict]:
        base = "orgs" if entity_type == "org" else "users"
        url  = f"https://api.github.com/{base}/{name}/repos?per_page=100&sort=updated"
        data = await self._gh_get(url, headers)
        return data if isinstance(data, list) else []

    # ── Org members ────────────────────────────────────────────────────────
    async def _get_members(self, org: str, headers: dict) -> list[str]:
        url  = f"https://api.github.com/orgs/{org}/members?per_page=100"
        data = await self._gh_get(url, headers)
        if isinstance(data, list):
            return [m.get("login", "") for m in data if m.get("login")]
        return []

    # ── Commit email harvesting ────────────────────────────────────────────
    async def _harvest_commit_emails(self, repos: list[dict], headers: dict) -> set[str]:
        emails: set[str] = set()
        sem = asyncio.Semaphore(20)

        async def _repo_commits(repo: dict):
            full_name = repo.get("full_name", "")
            if not full_name:
                return
            url = f"https://api.github.com/repos/{full_name}/commits?per_page=30"
            async with sem:
                data = await self._gh_get(url, headers)
                if isinstance(data, list):
                    for commit in data:
                        for role in ("author", "committer"):
                            c = commit.get("commit", {}).get(role, {})
                            e = c.get("email", "")
                            if e and "@" in e and "noreply" not in e:
                                emails.add(e.lower())

        await asyncio.gather(*[_repo_commits(r) for r in repos], return_exceptions=True)
        return emails

    # ── Flag interesting repos ─────────────────────────────────────────────
    def _flag_interesting_repos(self, repos: list[dict]) -> list[str]:
        interesting = []
        keywords = [
            "secret", "key", "password", "credential", "token", "config",
            "backup", "private", "internal", "infrastructure", "k8s",
            "deployment", "ansible", "terraform", "dotenv", ".env",
        ]
        for repo in repos:
            name = repo.get("name", "").lower()
            desc = repo.get("description", "") or ""
            desc = desc.lower()
            if any(kw in name or kw in desc for kw in keywords):
                interesting.append(repo.get("full_name", name))
        return interesting

    # ── Collect topics / languages ─────────────────────────────────────────
    def _collect_topics(self, repos: list[dict]) -> list[str]:
        topics: dict[str, int] = {}
        for repo in repos:
            for t in repo.get("topics", []):
                topics[t] = topics.get(t, 0) + 1
        return sorted(topics, key=topics.get, reverse=True)[:15]

    def _collect_languages(self, repos: list[dict]) -> list[str]:
        langs: dict[str, int] = {}
        for repo in repos:
            lang = repo.get("language")
            if lang:
                langs[lang] = langs.get(lang, 0) + 1
        return sorted(langs, key=langs.get, reverse=True)[:10]

    # ── Search by domain ───────────────────────────────────────────────────
    async def _search_by_domain(self, domain: str, headers: dict) -> dict:
        url  = f"https://api.github.com/search/users?q={domain}+in:email&per_page=5"
        data = await self._gh_get(url, headers)
        if isinstance(data, dict) and data.get("items"):
            return data["items"][0]
        return {}

    # ── Generic GET ───────────────────────────────────────────────────────
    async def _gh_get(self, url: str, headers: dict):
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            _r = await fetch(url, headers=headers, timeout=8)
            if _r["ok"]:
                return _r["json"]
            elif _r["status"] == 403:
                retry_after = _r["headers"].get("Retry-After")
                wait = float(retry_after) if retry_after is not None else 5.0
                await rate_limiter.on_rate_limited("api.github.com", wait)
            elif _r["status"] == 404:
                return {}
        except Exception as e:
            self.log.warning(f"GitHub API error {url}: {e}")
        return {}

    def _log_findings(self, r: dict) -> None:
        if r.get("name"):
            self.log.found("Name", r["name"])
        if r.get("github_url"):
            self.log.found("GitHub URL", r["github_url"])
        if r.get("public_repos"):
            self.log.found("Public Repos", str(r["public_repos"]))
        if r.get("member_count"):
            self.log.found("Members", str(r["member_count"]))
        if r.get("commit_emails"):
            self.log.found("Commit Emails", str(len(r["commit_emails"])))
        if r.get("interesting_repos"):
            for repo in r["interesting_repos"][:3]:
                self.log.warning(f"Interesting repo: {repo}")

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www.", "github.com/"):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
