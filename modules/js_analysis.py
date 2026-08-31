"""
modules/js_analysis.py
Phase 3 (cont.): Downloads discovered .js files, extracts hidden endpoints
(LinkFinder-style regex) and flags likely exposed secrets/API keys via a
custom regex engine, cross-checked with TruffleHog if installed.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

import aiohttp

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner

log = get_logger(__name__)

# LinkFinder-style endpoint extraction regex (paths, relative URLs, API routes).
ENDPOINT_REGEX = re.compile(
    r"""(?:"|')(
        (?:/[a-zA-Z0-9_?&=\-/.#%]+)               # relative paths
        |(?:https?://[a-zA-Z0-9_./?=&%\-]+)         # absolute URLs
    )(?:"|')""",
    re.VERBOSE,
)

# Custom secret-detection regex engine (common API key/token patterns).
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "github_token": re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}"),
    "generic_api_key": re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
    "firebase_url": re.compile(r"[a-z0-9-]+\.firebaseio\.com"),
}


async def _fetch_js(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.text(errors="ignore")
    except Exception as e:
        log.debug(f"Failed to fetch JS {url}: {e}")
    return None


async def _run_trufflehog(runner: ProcessRunner, cfg: ReconXConfig, js_content: str) -> list[dict]:
    """Optional cross-validation with TruffleHog if installed (filesystem scan mode)."""
    binary = cfg.tool_paths.get("trufflehog", "trufflehog")
    if not ProcessRunner.is_available(binary):
        return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(js_content)
        path = f.name
    findings = []
    try:
        res = await runner.run([binary, "filesystem", path, "--json", "--no-update"], timeout=60)
        import json
        for line in res.stdout.splitlines():
            try:
                obj = json.loads(line)
                findings.append({"type": obj.get("DetectorName", "trufflehog"),
                                  "snippet": obj.get("Raw", "")[:120]})
            except json.JSONDecodeError:
                continue
    finally:
        Path(path).unlink(missing_ok=True)
    return findings


async def analyze_js_files(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                            target: str, js_files: list[str]) -> dict:
    if not js_files:
        return {"new_endpoints": [], "secrets": []}

    log.info(f"[cyan]Phase 3[/cyan] — analyzing {len(js_files)} JS file(s) for endpoints & secrets")

    new_endpoints: set[str] = set()
    secrets: list[dict] = []

    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        for js_url in js_files:
            await runner.rate_limiter.acquire()
            content = await _fetch_js(session, js_url)
            if not content:
                continue

            for match in ENDPOINT_REGEX.finditer(content):
                path = match.group(1)
                if len(path) > 3:
                    new_endpoints.add(path)

            for label, pattern in SECRET_PATTERNS.items():
                for m in pattern.finditer(content):
                    snippet = m.group(0)[:120]
                    secrets.append({"js_url": js_url, "type": label, "snippet": snippet})
                    await db.add_secret_finding(target, js_url, label, snippet)

            th_findings = await _run_trufflehog(runner, cfg, content)
            for tf in th_findings:
                secrets.append({"js_url": js_url, "type": f"trufflehog:{tf['type']}", "snippet": tf["snippet"]})
                await db.add_secret_finding(target, js_url, f"trufflehog:{tf['type']}", tf["snippet"])

    for ep in new_endpoints:
        await db.add_endpoint(target, ep, source="js_analysis")

    if secrets:
        log.warning(f"[bold red]{len(secrets)} potential secret(s)[/bold red] found in JS files!")
    log.info(f"[green]{len(new_endpoints)} endpoints[/green] extracted from JS.")

    return {"new_endpoints": sorted(new_endpoints), "secrets": secrets}
