"""
reporting/notifier.py
Sends alerts to Discord/Slack webhooks for high-signal events: new subdomains
(diff mode), subdomain takeovers, critical vulnerabilities, and secrets found
in JS. Designed to be low-noise — call only with pre-filtered event lists.
"""
from __future__ import annotations

import aiohttp

from core.config import ReconXConfig
from core.logger import get_logger

log = get_logger(__name__)


async def _post_webhook(url: str, payload: dict):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status >= 300:
                    log.warning(f"Webhook returned status {resp.status}")
    except Exception as e:
        log.warning(f"Failed to send webhook notification: {e}")


async def notify_discord(webhook_url: str, title: str, lines: list[str]):
    if not webhook_url or not lines:
        return
    content = f"**{title}**\n" + "\n".join(f"• {line}" for line in lines[:25])
    if len(lines) > 25:
        content += f"\n…and {len(lines) - 25} more."
    await _post_webhook(webhook_url, {"content": content[:2000]})


async def notify_slack(webhook_url: str, title: str, lines: list[str]):
    if not webhook_url or not lines:
        return
    text = f"*{title}*\n" + "\n".join(f"- {line}" for line in lines[:25])
    if len(lines) > 25:
        text += f"\n…and {len(lines) - 25} more."
    await _post_webhook(webhook_url, {"text": text})


async def dispatch_alerts(cfg: ReconXConfig, event_type: str, title: str, lines: list[str]):
    notify_on = cfg.notifications.get("notify_on", [])
    if event_type not in notify_on or not lines:
        return
    discord_url = cfg.notifications.get("discord_webhook")
    slack_url = cfg.notifications.get("slack_webhook")
    if discord_url:
        await notify_discord(discord_url, title, lines)
    if slack_url:
        await notify_slack(slack_url, title, lines)
