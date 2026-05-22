"""
ProjectZ - Webhook Notifier
Push critical findings to Slack / Discord / generic webhook in real time.
Configure in .env:
  SLACK_WEBHOOK=https://hooks.slack.com/services/...
  DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
  NOTIFY_WEBHOOK=https://custom.webhook.url
  NOTIFY_SEVERITY=critical,high     # comma-separated, default=critical
"""

from __future__ import annotations
import asyncio
import json
import time
from src.core.config import config
from src.core.logger import OSINTLogger

log = OSINTLogger("notifier")

_NOTIFY_LEVELS = {s.strip().lower() for s in
                  getattr(config, "NOTIFY_SEVERITY", "critical").split(",")}


class _Notifier:

    def __init__(self):
        self.slack_url   = getattr(config, "SLACK_WEBHOOK", "") or ""
        self.discord_url = getattr(config, "DISCORD_WEBHOOK", "") or ""
        self.custom_url  = getattr(config, "NOTIFY_WEBHOOK", "") or ""
        self._enabled    = bool(self.slack_url or self.discord_url or self.custom_url)

    async def send(self, title: str, detail: str = "",
                   level: str = "info", target: str = "") -> bool:
        """Send notification. Returns True if sent to at least one destination."""
        if not self._enabled:
            return False
        if level.lower() not in _NOTIFY_LEVELS:
            return False

        sent = False
        emoji = {"critical": "🚨", "high": "⚠️", "medium": "ℹ️", "info": "📌"}.get(level, "📌")
        ts    = time.strftime("%Y-%m-%d %H:%M:%S")

        if self.slack_url:
            try:
                payload = {
                    "text": f"{emoji} *[ProjectZ | {level.upper()}]* {title}",
                    "attachments": [{
                        "color":  {"critical": "danger", "high": "warning"}.get(level, "good"),
                        "fields": [
                            {"title": "Target",  "value": target,  "short": True},
                            {"title": "Time",    "value": ts,      "short": True},
                            {"title": "Details", "value": detail[:300], "short": False},
                        ],
                    }],
                }
                sent = await self._post(self.slack_url, payload) or sent
            except Exception as e:
                log.debug(f"Slack notify error: {e}")

        if self.discord_url:
            try:
                color = {"critical": 15158332, "high": 16776960}.get(level, 3447003)
                payload = {
                    "embeds": [{
                        "title":       f"{emoji} {title}",
                        "description": detail[:2000],
                        "color":       color,
                        "footer":      {"text": f"ProjectZ • {ts} • {target}"},
                    }]
                }
                sent = await self._post(self.discord_url, payload) or sent
            except Exception as e:
                log.debug(f"Discord notify error: {e}")

        if self.custom_url:
            try:
                payload = {"title": title, "detail": detail,
                           "level": level, "target": target, "ts": ts}
                sent = await self._post(self.custom_url, payload) or sent
            except Exception as e:
                log.debug(f"Custom webhook error: {e}")

        return sent

    async def _post(self, url: str, payload: dict) -> bool:
        from src.core.http_client import fetch
        try:
            r = await fetch(url, method="post", json_data=payload, timeout=8)
            return r.get("ok", False) or r.get("status", 0) in (200, 204)
        except Exception:
            return False

    async def notify_finding(self, target: str, module: str,
                              title: str, severity: str, url: str = ""):
        """Called by engine for every critical/high finding."""
        detail = f"Module: {module}"
        if url:
            detail += f"\nURL: {url}"
        await self.send(title=f"[{module.upper()}] {title}",
                        detail=detail, level=severity, target=target)

    async def notify_scan_complete(self, target: str, risk_score: int,
                                    verdict: str, alert_count: int):
        """Called at end of scan with correlation summary."""
        if risk_score < 50:
            return
        level = "critical" if risk_score >= 75 else "high"
        await self.send(
            title   = f"Scan complete: {target} — {verdict}",
            detail  = f"Risk Score: {risk_score}/100\nAlerts: {alert_count}",
            level   = level,
            target  = target,
        )


notifier = _Notifier()
