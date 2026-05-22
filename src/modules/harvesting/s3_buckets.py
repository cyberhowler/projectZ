"""
ProjectZ - Module: Cloud Storage Bucket Finder
Discovers publicly accessible cloud storage buckets for:
  - AWS S3
  - Google Cloud Storage (GCS)
  - Azure Blob Storage
  - DigitalOcean Spaces
  - Alibaba OSS
Strategy:
  1. Permutation-based bucket name generation from domain
  2. DNS existence check (fast — no auth needed)
  3. HTTP probe for public read access (ListBucket response)
  4. Detects: public-read, public-read-write (CRITICAL), misconfigured ACL
  5. Extracts bucket contents listing if exposed
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

# Cloud storage URL templates
CLOUD_TEMPLATES: list[dict] = [
    {
        "name":    "AWS S3",
        "url":     "https://{bucket}.s3.amazonaws.com/",
        "url2":    "https://s3.amazonaws.com/{bucket}/",
        "xml_sig": "<ListBucketResult",
        "deny_sig": "AccessDenied",
        "open_sig": "<Key>",
    },
    {
        "name":    "GCS",
        "url":     "https://storage.googleapis.com/{bucket}/",
        "url2":    "https://{bucket}.storage.googleapis.com/",
        "xml_sig": "<ListBucketResult",
        "deny_sig": "AccessDenied",
        "open_sig": "<Key>",
    },
    {
        "name":    "Azure Blob",
        "url":     "https://{bucket}.blob.core.windows.net/?comp=list",
        "url2":    None,
        "xml_sig": "<EnumerationResults",
        "deny_sig": "AuthorizationFailure",
        "open_sig": "<Name>",
    },
    {
        "name":    "DigitalOcean Spaces",
        "url":     "https://{bucket}.nyc3.digitaloceanspaces.com/",
        "url2":    "https://{bucket}.ams3.digitaloceanspaces.com/",
        "xml_sig": "<ListBucketResult",
        "deny_sig": "AccessDenied",
        "open_sig": "<Key>",
    },
]

# Permutation generators
def _generate_bucket_names(domain: str) -> list[str]:
    base    = domain.replace(".", "-").replace("_", "-").lower()
    parts   = domain.split(".")
    name    = parts[0]
    company = name

    perms = set()
    # Direct name
    perms.add(base)
    perms.add(name)
    perms.add(company)
    # Common prefixes
    for prefix in ["dev", "staging", "stage", "prod", "production", "test",
                   "backup", "backups", "data", "static", "assets", "media",
                   "files", "uploads", "logs", "archive", "old", "new",
                   "internal", "private", "public", "www", "web", "admin",
                   "api", "cdn", "img", "images", "docs", "download"]:
        perms.add(f"{name}-{prefix}")
        perms.add(f"{prefix}-{name}")
        perms.add(f"{name}.{prefix}")
        perms.add(f"{company}{prefix}")
        perms.add(f"{prefix}{company}")
    # With domain base
    perms.add(f"{name}-bucket")
    perms.add(f"{name}-storage")
    perms.add(f"{name}-s3")
    perms.add(f"{name}-files")
    perms.add(f"{base}-backup")

    return list(perms)[:60]  # cap at 60 permutations


class S3BucketModule(BaseModule):
    MODULE_NAME = "s3buckets"
    DESCRIPTION = "Cloud bucket finder — AWS S3, GCS, Azure, DO Spaces | public read/write detection"

    async def run(self) -> dict:
        domain = self._clean(self.target)
        self.log.info(f"Cloud bucket scan: {domain}")

        cached = cache.get("s3buckets", domain)
        if cached and not self.options.get("no_cache"):
            return cached

        result: dict = {
            "domain":            domain,
            "buckets_found":     [],
            "open_buckets":      [],
            "writable_buckets":  [],
            "critical_findings": [],
            "total":             0,
        }

        bucket_names = _generate_bucket_names(domain)
        self.log.info(f"Testing {len(bucket_names)} bucket name permutations...")

        # Run all cloud providers concurrently (batched)
        sem    = asyncio.Semaphore(15)
        tasks  = []
        for bname in bucket_names:
            for cloud in CLOUD_TEMPLATES:
                tasks.append(self._check_bucket(sem, bname, cloud))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in all_results:
            if not isinstance(res, dict) or not res.get("found"):
                continue

            result["buckets_found"].append(res)
            bname = res.get("bucket_name", "")
            cloud = res.get("cloud", "")
            url   = res.get("url", "")
            acc   = res.get("access_level", "private")

            if acc == "public-read":
                result["open_buckets"].append(res)
                result["critical_findings"].append({
                    "title":    f"Public-Read Bucket: {bname} ({cloud})",
                    "severity": "high",
                    "detail":   f"Bucket publicly readable: {url}",
                    "url":      url,
                    "contents": res.get("sample_keys", [])[:5],
                })
                self.log.found("Open bucket", f"{cloud}: {bname} — PUBLIC READ")

            elif acc == "public-write":
                result["writable_buckets"].append(res)
                result["critical_findings"].append({
                    "title":    f"WRITABLE Bucket: {bname} ({cloud})",
                    "severity": "critical",
                    "detail":   f"Bucket allows public writes — CRITICAL data exposure risk: {url}",
                    "url":      url,
                })
                self.log.found("WRITABLE bucket!", f"{cloud}: {bname} — CRITICAL")

            elif acc == "exists":
                result["critical_findings"].append({
                    "title":    f"Bucket Exists (Private): {bname} ({cloud})",
                    "severity": "info",
                    "detail":   f"Bucket exists but access denied: {url}",
                    "url":      url,
                })

        result["total"] = len(result["buckets_found"])
        self.log.info(f"Buckets found: {result['total']} "
                      f"({len(result['open_buckets'])} open, "
                      f"{len(result['writable_buckets'])} writable)")

        cache.set("s3buckets", domain, result)
        await self._persist_db(result)
        return result

    async def _check_bucket(self, sem: asyncio.Semaphore,
                             bucket_name: str, cloud: dict) -> dict:
        async with sem:
            url = cloud["url"].format(bucket=bucket_name)
            try:
                resp = await fetch(url, timeout=6, return_headers=True)
                if not isinstance(resp, dict):
                    return {"found": False}

                status = resp.get("status_code", 0)
                body   = (resp.get("body", "") or "")[:4000]
                body_l = body.lower()

                # Bucket doesn't exist
                if status in (0, 404):
                    return {"found": False}

                # Bucket exists — check access level
                found_result = {
                    "found":        True,
                    "bucket_name":  bucket_name,
                    "cloud":        cloud["name"],
                    "url":          url,
                    "status":       status,
                    "access_level": "private",
                    "sample_keys":  [],
                }

                if cloud["xml_sig"] in body:
                    # ListBucket XML response = public read
                    found_result["access_level"] = "public-read"
                    # Extract some file keys
                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    found_result["sample_keys"] = keys[:10]

                elif cloud["deny_sig"] in body or status == 403:
                    found_result["access_level"] = "exists"

                elif status == 200:
                    found_result["access_level"] = "public-read"

                # Quick write test (HEAD PUT to see if writable — no actual upload)
                # Only test if bucket is already found
                if found_result["access_level"] in ("public-read", "exists"):
                    writable = await self._test_write(bucket_name, cloud)
                    if writable:
                        found_result["access_level"] = "public-write"

                return found_result

            except Exception:
                return {"found": False}

    async def _test_write(self, bucket_name: str, cloud: dict) -> bool:
        """Test if bucket allows public writes (OPTIONS method check only — no actual upload)."""
        url = cloud["url"].format(bucket=bucket_name) + "projectz_test_probe.txt"
        try:
            resp = await fetch(url, timeout=5, method="OPTIONS", return_headers=True)
            if not isinstance(resp, dict):
                return False
            allow = (resp.get("headers", {}) or {}).get("allow", "")
            return "PUT" in allow.upper()
        except Exception:
            return False
