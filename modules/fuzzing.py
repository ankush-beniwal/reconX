"""
modules/fuzzing.py
Phase 4: Context-aware directory/content fuzzing with ffuf (preferred, fast)
or feroxbuster. Wordlist selection adapts to detected tech stack, and a
dedicated sensitive-file pass checks for .env, .git, .DS_Store, backups, and
Swagger/OpenAPI docs on every live host.
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

SENSITIVE_FILES = [
    ".env", ".git/config", ".git/HEAD", ".DS_Store", "backup.zip", "backup.tar.gz",
    "db.sql", "dump.sql", "config.php.bak", "wp-config.php.bak", "swagger.json",
    "swagger-ui.html", "openapi.json", "api-docs", ".htaccess", "web.config",
    "composer.json", "package.json", ".npmrc", "id_rsa", ".aws/credentials",
]


def _pick_wordlist(cfg: ReconXConfig, tech: str) -> str:
    tech = (tech or "").lower()
    wl = cfg.wordlists
    if "php" in tech or "wordpress" in tech:
        return wl.get("content_php", wl.get("content_common", ""))
    if any(k in tech for k in ("node", "express", "go", "golang", "fastapi", "django")):
        return wl.get("content_api", wl.get("content_common", ""))
    return wl.get("content_common", "")


async def fuzz_host(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                     target: str, url: str, tech: str) -> list[dict]:
    wordlist = _pick_wordlist(cfg, tech)
    findings: list[dict] = []

    if wordlist and Path(wordlist).exists():
        out_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False).name
        try:
            if ProcessRunner.is_available(cfg.tool("ffuf")):
                cmd = [
                    cfg.tool("ffuf"), "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
                    "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", out_file,
                    "-t", "20", "-rate", str(cfg.general.get("rate_limit_rps", 15)), "-s",
                ]
                await runner.run(cmd, timeout=1200)
                if Path(out_file).exists():
                    try:
                        data = json.loads(Path(out_file).read_text())
                        for r in data.get("results", []):
                            findings.append({"url": r.get("url"), "status": r.get("status"),
                                              "length": r.get("length"), "source": "ffuf"})
                    except (json.JSONDecodeError, OSError):
                        pass
            elif ProcessRunner.is_available(cfg.tool("feroxbuster")):
                cmd = [cfg.tool("feroxbuster"), "-u", url, "-w", wordlist, "--json",
                       "-t", "20", "-q", "--silent"]
                res = await runner.run(cmd, timeout=1200)
                for line in res.stdout.splitlines():
                    try:
                        obj = json.loads(line)
                        if obj.get("type") == "response":
                            findings.append({"url": obj.get("url"), "status": obj.get("status"),
                                              "length": obj.get("content_length"), "source": "feroxbuster"})
                    except json.JSONDecodeError:
                        continue
        finally:
            Path(out_file).unlink(missing_ok=True)
    else:
        log.debug(f"No usable wordlist for tech='{tech}' — skipping brute-force pass for {url}")

    # Sensitive-file targeted check (always runs regardless of wordlist availability).
    sensitive_hits = await _check_sensitive_files(runner, url)
    findings.extend(sensitive_hits)

    for f_item in findings:
        await db.add_endpoint(target, f_item["url"], source=f"fuzz:{f_item.get('source','sensitive')}")

    return findings


async def _check_sensitive_files(runner: ProcessRunner, base_url: str) -> list[dict]:
    hits = []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(f"{base_url.rstrip('/')}/{path}" for path in SENSITIVE_FILES))
        url_list = f.name
    try:
        if ProcessRunner.is_available("httpx"):
            res = await runner.run(
                ["httpx", "-list", url_list, "-silent", "-json", "-status-code", "-mc", "200,301,302,403"],
                timeout=300,
            )
            for line in res.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    hits.append({"url": obj.get("url"), "status": obj.get("status_code"),
                                 "source": "sensitive_file", "length": None})
                except json.JSONDecodeError:
                    continue
    finally:
        Path(url_list).unlink(missing_ok=True)
    if hits:
        log.warning(f"[bold red]{len(hits)} sensitive file(s) exposed[/bold red] on {base_url}")
    return hits


async def fuzz_all(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                    target: str, live_hosts: list[dict]) -> list[dict]:
    import asyncio
    log.info(f"[cyan]Phase 4[/cyan] — smart content discovery on {len(live_hosts)} host(s)")
    tasks = [fuzz_host(runner, cfg, db, target, h["url"], h.get("tech", "")) for h in live_hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_findings = []
    for r in results:
        if isinstance(r, list):
            all_findings.extend(r)
    log.info(f"[green]{len(all_findings)} content-discovery findings[/green] total.")
    return all_findings
