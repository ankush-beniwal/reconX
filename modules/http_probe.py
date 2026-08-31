"""
modules/http_probe.py
Phase 2b: HTTP probing via httpx — status codes, titles, tech stack, TLS certs,
and basic CDN detection (Cloudflare/Akamai/Fastly/etc via header + CNAME heuristics).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner

log = get_logger(__name__)

CDN_HEADER_SIGNATURES = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly", "x-served-by"],
    "cloudfront": ["x-amz-cf-id", "cloudfront"],
    "incapsula": ["x-iinfo", "incap_ses"],
}


def _detect_cdn(headers: dict) -> str | None:
    header_blob = " ".join(f"{k}:{v}".lower() for k, v in (headers or {}).items())
    for cdn, sigs in CDN_HEADER_SIGNATURES.items():
        if any(sig in header_blob for sig in sigs):
            return cdn
    return None


async def probe_http(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                      target: str, hosts: list[str]) -> list[dict]:
    if not hosts:
        return []

    log.info(f"[cyan]Phase 2[/cyan] — HTTP probing {len(hosts)} host(s) with httpx")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts))
        input_path = f.name

    live: list[dict] = []
    try:
        cmd = [
            cfg.tool("httpx"), "-list", input_path, "-json", "-silent",
            "-status-code", "-title", "-tech-detect", "-tls-grab",
            "-follow-redirects", "-timeout", "10",
        ]
        res = await runner.run(cmd, timeout=1200)
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            cdn = _detect_cdn(obj.get("header", {})) or ("cloudflare" if obj.get("cdn") else None)
            entry = {
                "url": obj.get("url"),
                "status_code": obj.get("status_code"),
                "title": obj.get("title", ""),
                "tech": ",".join(obj.get("tech", [])) if obj.get("tech") else "",
                "cdn": cdn or "",
                "ip": obj.get("host") if _looks_like_ip(obj.get("host", "")) else obj.get("a", [""])[0] if obj.get("a") else "",
                "tls_cn": (obj.get("tls", {}) or {}).get("subject_cn", ""),
            }
            live.append(entry)
            await db.add_live_host(
                target=target, url=entry["url"], status_code=entry["status_code"] or 0,
                title=entry["title"], tech=entry["tech"], cdn=entry["cdn"], ip=entry["ip"],
            )
    finally:
        Path(input_path).unlink(missing_ok=True)

    log.info(f"[green]{len(live)} live HTTP hosts[/green] confirmed.")
    return live


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
