"""
modules/vuln_scan.py
Phase 5: Automated vulnerability & misconfig scanning via nuclei (filtered to
cves/exposures/misconfigurations/default-logins + critical/high severity to
reduce noise), plus lightweight custom checks for CORS misconfig, open
redirect, and SSRF-prone parameters.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import aiohttp

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner

log = get_logger(__name__)

OPEN_REDIRECT_PARAMS = {"redirect", "url", "next", "return", "returnurl", "dest",
                         "destination", "continue", "redir", "target"}
SSRF_PARAMS = {"url", "uri", "path", "dest", "redirect", "target", "callback",
                "webhook", "feed", "host", "site"}


async def run_nuclei(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                      target: str, urls: list[str]) -> list[dict]:
    if not urls:
        return []

    log.info(f"[cyan]Phase 5[/cyan] — nuclei scan on {len(urls)} URL(s)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        input_path = f.name

    findings: list[dict] = []
    try:
        tags = ",".join(cfg.nuclei.get("tags", ["cves", "exposures", "misconfiguration", "default-logins"]))
        severity = ",".join(cfg.nuclei.get("severity", ["critical", "high"]))
        cmd = [
            cfg.tool("nuclei"), "-list", input_path, "-tags", tags, "-severity", severity,
            "-jsonl", "-silent", "-rate-limit", str(cfg.nuclei.get("rate_limit", 150)),
            "-bulk-size", str(cfg.nuclei.get("bulk_size", 25)),
        ]
        res = await runner.run(cmd, timeout=3600)
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            entry = {
                "url": obj.get("matched-at") or obj.get("host"),
                "template_id": obj.get("template-id"),
                "severity": info.get("severity"),
                "description": info.get("name"),
            }
            findings.append(entry)
            await db.add_vulnerability(target, entry["url"], entry["template_id"],
                                        entry["severity"], entry["description"])
    finally:
        Path(input_path).unlink(missing_ok=True)

    crit = [f for f in findings if f["severity"] == "critical"]
    if crit:
        log.error(f"[bold red]{len(crit)} CRITICAL[/bold red] finding(s) from nuclei!")
    log.info(f"[green]{len(findings)} nuclei finding(s)[/green] total.")
    return findings


async def check_cors(session: aiohttp.ClientSession, url: str) -> dict | None:
    """Sends an Origin header from an attacker-controlled domain and checks reflection."""
    evil_origin = "https://evil-recon-probe.example"
    try:
        async with session.get(url, headers={"Origin": evil_origin},
                                timeout=aiohttp.ClientTimeout(total=10)) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == evil_origin or acao == "*" and acac.lower() == "true":
                return {"url": url, "issue": "CORS misconfiguration",
                        "detail": f"ACAO reflects arbitrary origin (ACAO={acao}, ACAC={acac})"}
    except Exception as e:
        log.debug(f"CORS check failed for {url}: {e}")
    return None


def flag_open_redirect_params(url: str) -> dict | None:
    parsed = urlparse(url)
    params = set(parse_qs(parsed.query).keys())
    hit = params & OPEN_REDIRECT_PARAMS
    if hit:
        return {"url": url, "issue": "Potential open redirect", "detail": f"suspicious param(s): {hit}"}
    return None


def flag_ssrf_params(url: str) -> dict | None:
    parsed = urlparse(url)
    params = set(parse_qs(parsed.query).keys())
    hit = params & SSRF_PARAMS
    if hit:
        return {"url": url, "issue": "Potential SSRF sink", "detail": f"suspicious param(s): {hit}"}
    return None


async def run_misconfig_checks(runner: ProcessRunner, urls: list[str]) -> list[dict]:
    """CORS + open redirect + SSRF param flagging — cheap heuristics, not exploitation."""
    log.info(f"[cyan]Phase 5[/cyan] — CORS/open-redirect/SSRF heuristic checks on {len(urls)} URL(s)")
    findings = []

    for url in urls:
        or_hit = flag_open_redirect_params(url)
        if or_hit:
            findings.append(or_hit)
        ssrf_hit = flag_ssrf_params(url)
        if ssrf_hit:
            findings.append(ssrf_hit)

    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        for url in urls:
            await runner.rate_limiter.acquire()
            cors_hit = await check_cors(session, url)
            if cors_hit:
                findings.append(cors_hit)

    if findings:
        log.warning(f"[yellow]{len(findings)} misconfiguration heuristic hit(s)[/yellow] flagged for manual review.")
    return findings
