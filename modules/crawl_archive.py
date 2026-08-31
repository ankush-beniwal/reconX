"""
modules/crawl_archive.py
Phase 3: Deep URL/endpoint discovery via active crawling (katana) and
historical archive mining (gau, waybackurls). Also isolates JS file URLs
for the js_analysis module.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner
from core.scope import ScopeFilter

log = get_logger(__name__)


async def crawl_and_archive(runner: ProcessRunner, cfg: ReconXConfig, db: ReconDB,
                             scope: ScopeFilter, target: str, live_urls: list[str]) -> dict:
    if not live_urls:
        return {"endpoints": [], "js_files": []}

    log.info(f"[cyan]Phase 3[/cyan] — crawling & archive mining ({len(live_urls)} seed URLs)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(live_urls))
        input_path = f.name

    all_urls: set[str] = set()
    try:
        if ProcessRunner.is_available(cfg.tool("katana")):
            res = await runner.run(
                [cfg.tool("katana"), "-list", input_path, "-silent", "-jc",
                 "-d", "3", "-timeout", "10"],
                timeout=1800,
            )
            all_urls.update(line.strip() for line in res.stdout.splitlines() if line.strip())

        # gau/waybackurls operate per-domain, not per-URL-list; derive root domains.
        domains = sorted({_root_host(u) for u in live_urls})
        for domain in domains:
            if ProcessRunner.is_available(cfg.tool("gau")):
                res = await runner.run([cfg.tool("gau"), "--subs", domain], timeout=600)
                all_urls.update(line.strip() for line in res.stdout.splitlines() if line.strip())
            if ProcessRunner.is_available(cfg.tool("waybackurls")):
                res = await runner.run([cfg.tool("waybackurls"), domain], timeout=600)
                all_urls.update(line.strip() for line in res.stdout.splitlines() if line.strip())
    finally:
        Path(input_path).unlink(missing_ok=True)

    # Scope filter by hostname
    in_scope_urls = {u for u in all_urls if scope.is_in_scope(_root_host(u))}
    js_files = sorted({u for u in in_scope_urls if u.split("?")[0].endswith(".js")})
    endpoints = sorted(in_scope_urls - set(js_files))

    for url in endpoints:
        await db.add_endpoint(target, url, source="katana/gau/wayback")

    log.info(f"[green]{len(endpoints)} endpoints[/green], [green]{len(js_files)} JS files[/green] discovered.")
    return {"endpoints": endpoints, "js_files": js_files}


def _root_host(url: str) -> str:
    try:
        no_scheme = url.split("://", 1)[-1]
        host = no_scheme.split("/", 1)[0]
        return host.split(":")[0].lower()
    except Exception:
        return ""
