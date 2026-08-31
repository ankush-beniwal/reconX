"""
core/orchestrator.py
The pipeline controller. Wires config -> scope -> db -> process runner ->
phase modules, in order, with resume support (skip phases already marked
'done' for a target unless --force is passed) and diff-mode alerting.
"""
from __future__ import annotations

import time

from core.config import ReconXConfig
from core.database import ReconDB
from core.logger import get_logger
from core.process import ProcessRunner
from core.scope import ScopeFilter
from modules import (
    crawl_archive,
    fuzzing,
    http_probe,
    js_analysis,
    param_mining,
    permute_resolve,
    port_scan,
    subdomain_enum,
    vuln_scan,
)
from reporting import notifier, report_generator

log = get_logger(__name__)

PHASES = [
    "subdomain_enum",
    "permute_resolve",
    "takeover_check",
    "port_scan",
    "http_probe",
    "crawl_archive",
    "js_analysis",
    "param_mining",
    "fuzzing",
    "vuln_scan",
]


class Orchestrator:
    def __init__(self, cfg: ReconXConfig, force: bool = False):
        self.cfg = cfg
        self.force = force
        self.db: ReconDB | None = None
        self.scope: ScopeFilter | None = None
        self.runner: ProcessRunner | None = None

    async def setup(self):
        self.db = await ReconDB(self.cfg.db_path()).connect()
        self.scope = ScopeFilter(self.cfg.general["scope_file"])
        self.runner = ProcessRunner(
            concurrency=self.cfg.general.get("concurrency", 25),
            rate_limit_rps=self.cfg.general.get("rate_limit_rps", 15),
            default_timeout=self.cfg.general.get("timeout_seconds", 600),
        )

    async def teardown(self):
        if self.db:
            await self.db.close()

    async def _should_skip(self, target: str, phase: str) -> bool:
        if self.force or not self.cfg.general.get("resume", True):
            return False
        status = await self.db.get_phase_status(target, phase)
        return status == "done"

    async def _mark(self, target: str, phase: str, status: str):
        await self.db.set_phase_status(target, phase, status)

    async def run_target(self, target: str) -> dict:
        """Runs the full pipeline for one root domain. Returns the aggregated result dict."""
        run_start_ts = time.time()
        run_id = await self.db.start_run(target)
        result: dict = {"target": target, "run_id": run_id, "started_at": run_start_ts}

        if not self.scope.is_in_scope(target):
            log.error(f"[red]Target '{target}' is not in scope per scope file — aborting.[/red]")
            result["error"] = "out_of_scope"
            return result

        # --- Phase 1: Subdomain enumeration -------------------------------------------------
        if not await self._should_skip(target, "subdomain_enum"):
            await self._mark(target, "subdomain_enum", "running")
            subdomains = await subdomain_enum.enumerate_subdomains(
                self.runner, self.cfg, self.db, self.scope, target
            )
            await self._mark(target, "subdomain_enum", "done")
        else:
            log.info(f"[dim]Skipping subdomain_enum for {target} (resume)[/dim]")
            subdomains = [r["subdomain"] for r in await self.db.all_for_target("subdomains", target)]
        result["subdomains"] = subdomains

        # --- Phase 1b: Permutation + resolution + takeover ----------------------------------
        if not await self._should_skip(target, "permute_resolve"):
            await self._mark(target, "permute_resolve", "running")
            perms = await permute_resolve.generate_permutations(self.runner, self.cfg, subdomains)
            resolved = await permute_resolve.resolve_candidates(self.runner, self.cfg, perms)
            resolved_in_scope = self.scope.filter_list(resolved)
            for sub in resolved_in_scope:
                await self.db.add_subdomain(target, sub, source="permutation")
            subdomains = sorted(set(subdomains) | set(resolved_in_scope))
            await self._mark(target, "permute_resolve", "done")
        result["subdomains"] = subdomains

        if not await self._should_skip(target, "takeover_check"):
            await self._mark(target, "takeover_check", "running")
            takeovers = await permute_resolve.check_takeovers(self.runner, self.cfg, subdomains)
            await self._mark(target, "takeover_check", "done")
        else:
            takeovers = []
        result["takeovers"] = takeovers

        # --- Phase 2: Port scan + HTTP probing -----------------------------------------------
        if not await self._should_skip(target, "port_scan"):
            await self._mark(target, "port_scan", "running")
            open_ports = await port_scan.scan_ports(self.runner, self.cfg, self.db, target, subdomains)
            await self._mark(target, "port_scan", "done")
        else:
            open_ports = {}
        result["open_ports"] = open_ports

        if not await self._should_skip(target, "http_probe"):
            await self._mark(target, "http_probe", "running")
            live_hosts = await http_probe.probe_http(self.runner, self.cfg, self.db, target, subdomains)
            await self._mark(target, "http_probe", "done")
        else:
            live_hosts = [r for r in await self.db.all_for_target("live_hosts", target)]
        result["live_hosts"] = live_hosts
        live_urls = [h["url"] for h in live_hosts if h.get("url")]

        # --- Phase 3: Crawling, archives, JS analysis, param mining --------------------------
        if not await self._should_skip(target, "crawl_archive"):
            await self._mark(target, "crawl_archive", "running")
            crawl_result = await crawl_archive.crawl_and_archive(
                self.runner, self.cfg, self.db, self.scope, target, live_urls
            )
            await self._mark(target, "crawl_archive", "done")
        else:
            crawl_result = {"endpoints": [], "js_files": []}
        result["endpoints"] = crawl_result["endpoints"]

        if not await self._should_skip(target, "js_analysis"):
            await self._mark(target, "js_analysis", "running")
            js_result = await js_analysis.analyze_js_files(
                self.runner, self.cfg, self.db, target, crawl_result["js_files"]
            )
            await self._mark(target, "js_analysis", "done")
        else:
            js_result = {"new_endpoints": [], "secrets": []}
        result["secrets"] = js_result["secrets"]
        result["endpoints"] = sorted(set(result["endpoints"]) | set(js_result["new_endpoints"]))

        if not await self._should_skip(target, "param_mining"):
            await self._mark(target, "param_mining", "running")
            params = await param_mining.mine_parameters(self.runner, self.cfg, live_urls[:200])
            await self._mark(target, "param_mining", "done")
        else:
            params = {}
        result["parameters"] = params

        # --- Phase 4: Smart fuzzing -------------------------------------------------------------
        if not await self._should_skip(target, "fuzzing"):
            await self._mark(target, "fuzzing", "running")
            fuzz_findings = await fuzzing.fuzz_all(self.runner, self.cfg, self.db, target, live_hosts)
            await self._mark(target, "fuzzing", "done")
        else:
            fuzz_findings = []
        result["fuzzing_findings"] = fuzz_findings

        # --- Phase 5: Vulnerability + misconfig scanning ----------------------------------------
        scan_urls = sorted(set(live_urls) | set(result["endpoints"]))[:5000]
        if not await self._should_skip(target, "vuln_scan"):
            await self._mark(target, "vuln_scan", "running")
            vulns = await vuln_scan.run_nuclei(self.runner, self.cfg, self.db, target, live_urls)
            misconfig = await vuln_scan.run_misconfig_checks(self.runner, scan_urls[:500])
            await self._mark(target, "vuln_scan", "done")
        else:
            vulns, misconfig = [], []
        result["vulnerabilities"] = vulns
        result["misconfig_findings"] = misconfig

        result["finished_at"] = time.time()
        await self.db.finish_run(run_id)

        await self._send_alerts(target, result, run_start_ts)
        return result

    async def _send_alerts(self, target: str, result: dict, run_start_ts: float):
        diff_mode = self.cfg.general.get("diff_mode", False)

        if diff_mode:
            new_subs = await self.db.new_since("subdomains", target, run_start_ts)
            if new_subs:
                await notifier.dispatch_alerts(
                    self.cfg, "new_subdomain", f"New subdomains — {target}",
                    [r["subdomain"] for r in new_subs],
                )

        if result.get("takeovers"):
            await notifier.dispatch_alerts(
                self.cfg, "subdomain_takeover", f"Possible subdomain takeover — {target}",
                [f"{t.get('subdomain')} ({t.get('tool')})" for t in result["takeovers"]],
            )

        critical_vulns = [v for v in result.get("vulnerabilities", []) if v.get("severity") == "critical"]
        if critical_vulns:
            await notifier.dispatch_alerts(
                self.cfg, "critical_vuln", f"CRITICAL vulnerabilities — {target}",
                [f"{v['url']} — {v['description']} ({v['template_id']})" for v in critical_vulns],
            )

        if result.get("secrets"):
            await notifier.dispatch_alerts(
                self.cfg, "new_endpoint_secret", f"Secrets found in JS — {target}",
                [f"{s['js_url']} — {s['type']}" for s in result["secrets"]],
            )

    def build_report(self, result: dict):
        formats = self.cfg.reporting.get("formats", ["json", "markdown", "html"])
        return report_generator.write_reports(result, self.cfg.output_dir(), formats)
