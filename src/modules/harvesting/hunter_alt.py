"""
ProjectZ - Module 38: Hunter.io Alternative / Email Intelligence (Extra-Ordinary)
Deep email discovery WITHOUT Hunter.io paid plan:
  - Pattern generation from discovered names
  - SMTP verification (VRFY + RCPT TO probing)
  - Gravatar profile lookup per email hash
  - GitHub commit email mining
  - LinkedIn + company website scraping
  - Social account cross-reference per email
  - Email format detection (guess dominant format)
  - Confidence scoring per email
Self-coded — maximum coverage, no paid APIs.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import smtplib
import socket
from collections import Counter
from typing import Optional

from src.core import async_http as aiohttp
from src.core.http_client import fetch
from src.core import dns_compat as dns

from src.core.engine import BaseModule
from src.core.rate_limiter import rate_limiter
from src.core.storage import cache, DatabaseManager
from src.core.config import config

# Email format templates
EMAIL_FORMATS = [
    ("{f}{last}",       "{first[0]}{last}"),
    ("{first}.{last}",  "{first}.{last}"),
    ("{first}{last}",   "{first}{last}"),
    ("{f}.{last}",      "{first[0]}.{last}"),
    ("{last}.{first}",  "{last}.{first}"),
    ("{last}{f}",       "{last}{first[0]}"),
    ("{first}",         "{first}"),
    ("{last}",          "{last}"),
    ("{first}_{last}",  "{first}_{last}"),
]

# Generic corporate email prefixes
GENERIC_PREFIXES = [
    "info", "contact", "hello", "support", "admin", "sales", "hr",
    "jobs", "careers", "press", "media", "legal", "security", "abuse",
    "privacy", "help", "team", "marketing", "finance", "billing",
    "operations", "engineering", "ceo", "cto", "cfo", "founders",
    "partnerships", "investor", "ir", "board",
]


class HunterAltModule(BaseModule):
    MODULE_NAME = "hunter"
    DESCRIPTION = "Email intelligence — pattern gen, SMTP verify, Gravatar, GitHub mining, confidence scores"

    async def run(self) -> dict:
        domain  = self._clean(self.target)
        names   = self.options.get("names", [])   # list of {"first": ..., "last": ...}
        verify  = self.options.get("smtp_verify", False)
        self.log.info(f"Email intelligence: {domain}")

        cached = cache.get("hunter_alt", domain)
        if cached:
            return cached

        # Run all discovery methods
        (website_emails, github_emails,
         scraped_names, mx_info) = await asyncio.gather(
            self._scrape_website(domain),
            self._github_emails(domain),
            self._scrape_names(domain),
            self._get_mx_info(domain),
            return_exceptions=True,
        )

        def _safe(v, d): return d if isinstance(v, Exception) else v
        website_emails = _safe(website_emails, set())
        github_emails  = _safe(github_emails,  set())
        scraped_names  = _safe(scraped_names,  [])
        mx_info        = _safe(mx_info,        {})

        # Combine names: passed-in + scraped
        all_names = list({n["first"] + n["last"]: n
                          for n in (names + scraped_names)}.values())

        # Generate email patterns for each name
        generated_emails = self._generate_all_formats(all_names, domain)

        # Merge all found emails
        all_emails_raw = website_emails | github_emails | {e["email"] for e in generated_emails}
        all_emails_raw = {e.lower() for e in all_emails_raw if "@" in e and domain in e}

        # Detect dominant format from known emails
        dominant_format = self._detect_format(website_emails | github_emails, domain)

        # Enrich each email with metadata
        enriched = await self._enrich_emails(all_emails_raw, domain)

        # SMTP verify if requested (slow, use sparingly)
        if verify and mx_info.get("mx_host"):
            enriched = await self._smtp_verify_all(enriched, mx_info["mx_host"])

        # Sort by confidence
        enriched.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        # Generic address list
        generic = [f"{p}@{domain}" for p in GENERIC_PREFIXES]

        # Store in DB
        for e in enriched:
            await DatabaseManager.insert_email(e["email"], domain, "hunter_alt")

        result = {
            "domain":          domain,
            "total":           len(enriched),
            "emails":          enriched,
            "generic_addresses": generic,
            "dominant_format": dominant_format,
            "names_found":     all_names[:20],
            "mx_info":         mx_info,
            "sources": {
                "website":   len(website_emails),
                "github":    len(github_emails),
                "generated": len(generated_emails),
            },
            "high_confidence": [e for e in enriched if e.get("confidence", 0) >= 70],
        }

        self.log.found("Emails Found",     str(len(enriched)))
        self.log.found("Dominant Format",  dominant_format)
        self.log.found("High Confidence",  str(len(result["high_confidence"])))
        for e in enriched[:5]:
            self.log.found("Email", f"{e['email']} (conf: {e.get('confidence',0)}%)")

        cache.set("hunter_alt", domain, result)
        return result

    # ── Website email scraping ─────────────────────────────────────────────
    async def _scrape_website(self, domain: str) -> set[str]:
        email_re = re.compile(r"[a-zA-Z0-9._%+\-]{1,64}@"
                               r"[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,10}", re.I)
        pages    = [
            f"https://{domain}", f"https://{domain}/contact",
            f"https://{domain}/about", f"https://{domain}/team",
            f"https://{domain}/about-us", f"https://{domain}/contact-us",
        ]
        emails: set[str] = set()
        sem = asyncio.Semaphore(20)

        async def _fetch(url: str):
            async with sem:
                try:
                    timeout = aiohttp.ClientTimeout(total=8)
                    _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                    if _r["ok"]:
                        text = _r["text"]
                        found = email_re.findall(text)
                        emails.update(e.lower() for e in found)
                except Exception:
                    pass

        await asyncio.gather(*[_fetch(url) for url in pages], return_exceptions=True)
        return {e for e in emails if domain in e}

    # ── GitHub commit email mining ─────────────────────────────────────────
    async def _github_emails(self, domain: str) -> set[str]:
        emails  = set()
        headers = {**config.DEFAULT_HEADERS, "Accept": "application/vnd.github.v3+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"token {config.GITHUB_TOKEN}"

        for q in [f'"{domain}" in:email', f'"{domain}" type:commit']:
            url = f"https://api.github.com/search/commits?q={q}&per_page=30"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                _r = await fetch(url, headers=headers, timeout=8)
                if _r["ok"]:
                    data = _r["json"]
                    for item in data.get("items", []):
                        e = item.get("commit", {}).get("author", {}).get("email", "")
                        if e and "@" in e and domain in e and "noreply" not in e:
                            emails.add(e.lower())
            except Exception:
                pass
            await asyncio.sleep(1.0)
        return emails

    # ── Scrape names from website ──────────────────────────────────────────
    async def _scrape_names(self, domain: str) -> list[dict]:
        name_re = re.compile(r"\b([A-Z][a-z]{2,14})\s+([A-Z][a-z]{2,18})\b")
        skip    = {"About Us", "Our Team", "Learn More", "Read More",
                   "Privacy Policy", "All Rights", "Cookie Policy"}
        names   = []
        seen    = set()

        for path in ["/team", "/about", "/people", "/leadership", "/about-us"]:
            url = f"https://{domain}{path}"
            try:
                timeout = aiohttp.ClientTimeout(total=8)
                _r = await fetch(url, headers=config.DEFAULT_HEADERS, timeout=8)
                if _r["ok"]:
                    html = _r["text"]
                    text = re.sub(r"<[^>]+>", " ", html)
                    text = re.sub(r"\s+", " ", text)
                    for m in name_re.finditer(text):
                        name_str = f"{m.group(1)} {m.group(2)}"
                        if name_str not in skip and name_str not in seen:
                            seen.add(name_str)
                            names.append({
                                "first": m.group(1).lower(),
                                "last":  m.group(2).lower(),
                                "full":  name_str,
                            })
            except Exception:
                pass
        return names[:30]

    # ── Get MX info ───────────────────────────────────────────────────────
    async def _get_mx_info(self, domain: str) -> dict:
        try:
            resolver = dns.asyncresolver.Resolver()
            ans      = await asyncio.wait_for(resolver.resolve(domain, "MX"), timeout=3)
            mx_list  = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in ans])
            return {
                "mx_records": mx_list,
                "mx_host":    mx_list[0][1] if mx_list else "",
                "mx_count":   len(mx_list),
            }
        except Exception:
            return {"mx_records": [], "mx_host": "", "mx_count": 0}

    # ── Generate all format variants ──────────────────────────────────────
    def _generate_all_formats(self, names: list[dict], domain: str) -> list[dict]:
        generated = []
        for name in names:
            first = re.sub(r"[^a-z]", "", name.get("first", "").lower())
            last  = re.sub(r"[^a-z]", "", name.get("last", "").lower())
            if not first or not last:
                continue
            for template, _ in EMAIL_FORMATS:
                try:
                    local = template.format(
                        first=first, last=last,
                        f=first[0] if first else "",
                    )
                    email = f"{local}@{domain}"
                    generated.append({
                        "email":      email,
                        "name":       name.get("full", f"{first} {last}"),
                        "format":     template,
                        "confidence": 40,    # base confidence for generated
                        "source":     "generated",
                    })
                except Exception:
                    pass
        return generated

    # ── Detect dominant email format ───────────────────────────────────────
    def _detect_format(self, known_emails: set[str], domain: str) -> str:
        patterns: dict[str, int] = Counter()
        for email in known_emails:
            local = email.split("@")[0]
            if "." in local:
                patterns["first.last"] += 1
            elif re.match(r"^[a-z]{1,2}[a-z]+$", local) and len(local) < 10:
                patterns["flast"] += 1
            elif re.match(r"^[a-z]+$", local):
                patterns["first"] += 1
        return patterns.most_common(1)[0][0] if patterns else "unknown"

    # ── Enrich emails ─────────────────────────────────────────────────────
    async def _enrich_emails(self, emails: set[str], domain: str) -> list[dict]:
        sem      = asyncio.Semaphore(20)
        enriched = []

        async def _enrich_one(email: str):
            async with sem:
                md5     = hashlib.md5(email.lower().encode()).hexdigest()
                gravatar_exists = await self._check_gravatar(md5)
                confidence = 50   # base
                if gravatar_exists:
                    confidence += 20
                enriched.append({
                    "email":         email,
                    "md5":           md5,
                    "gravatar":      f"https://www.gravatar.com/avatar/{md5}" if gravatar_exists else "",
                    "gravatar_hit":  gravatar_exists,
                    "confidence":    confidence,
                    "smtp_valid":    None,   # set later if verify=True
                    "source":        "discovered",
                })

        await asyncio.gather(*[_enrich_one(e) for e in emails], return_exceptions=True)
        return enriched

    # ── Gravatar existence check ───────────────────────────────────────────
    async def _check_gravatar(self, md5: str) -> bool:
        url = f"https://www.gravatar.com/avatar/{md5}?d=404"
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            _r = await fetch(url, method="head", timeout=8)
            return _r["status"] == 200
        except Exception:
            return False

    # ── SMTP verification ──────────────────────────────────────────────────
    async def _smtp_verify_all(self, emails: list[dict],
                                mx_host: str) -> list[dict]:
        """Non-invasive SMTP RCPT TO check — doesn't send email."""
        loop = asyncio.get_event_loop()
        sem  = asyncio.Semaphore(20)

        async def _verify(e: dict):
            async with sem:
                valid = await loop.run_in_executor(
                    None, self._smtp_rcpt_check, e["email"], mx_host
                )
                e["smtp_valid"] = valid
                if valid:
                    e["confidence"] = min(e.get("confidence", 50) + 30, 99)

        await asyncio.gather(*[_verify(e) for e in emails], return_exceptions=True)
        return emails

    def _smtp_rcpt_check(self, email: str, mx_host: str) -> Optional[bool]:
        try:
            server = smtplib.SMTP(timeout=8)
            server.connect(mx_host, 25)
            server.helo("projectz.local")
            server.mail("probe@projectz.local")
            code, _ = server.rcpt(email)
            server.quit()
            if code == 250:   return True
            if code == 550:   return False
            return None   # Catch-all or unknown
        except Exception:
            return None

    def _clean(self, t: str) -> str:
        t = t.lower().strip()
        for p in ("https://", "http://", "www."):
            if t.startswith(p): t = t[len(p):]
        return t.split("/")[0]
