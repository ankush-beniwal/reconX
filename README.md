# ReconX

A modular, async, high-performance recon and asset-discovery framework for **authorized** bug bounty and pentest engagements. Orchestrates best-in-class open-source recon tools behind a clean Python pipeline with state tracking, resume/diff support, strict scope enforcement, and Discord/Slack alerting.

> ⚠️ **Only run this against assets you are explicitly authorized to test.** The scope file is a safety mechanism, not a legal substitute for a signed engagement/bug-bounty program authorization.

---

## 1. Architecture

See the file tree in the project root. In short:

- `core/` — config loading, logging, SQLite state/diff engine, scope filter, async subprocess runner (concurrency + rate limiting).
- `modules/` — one file per recon phase, each a thin async wrapper around a CLI tool (or a small set of tools) plus scope filtering and DB persistence.
- `reporting/` — Markdown/HTML/JSON report generation + webhook notifier.
- `core/orchestrator.py` — the pipeline: runs phases in order, respects `--force`/resume state, and fires alerts.
- `main.py` — CLI entrypoint.

Every phase writes structured results to SQLite (`data/reconx.db`) as it goes, so a killed/interrupted run can be resumed with no duplicate work (`resume: true` in config, phase-level checkpointing).

---

## 2. Prerequisites

- Python 3.11+
- Go 1.21+ (for the Go-based recon tools — skip if using Docker)
- `git`, `unzip`, `build-essential` / equivalent
- (Optional but recommended) Docker, if you'd rather not install ~15 Go tools locally

---

## 3. Local Installation (bare metal)

### 3.1 Clone and set up Python environment
```bash
git clone <your-fork-or-repo-url> reconx && cd reconx
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3.2 Install the Go-based recon tools
```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/LukaSikic/subzy@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

> `naabu` needs `libpcap-dev` (`sudo apt install libpcap-dev`) for SYN scan mode.

### 3.3 Install remaining tools
```bash
# amass
sudo snap install amass          # or download the release binary for your platform

# massdns
git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo cp bin/massdns /usr/local/bin && cd ..

# findomain
curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin

# feroxbuster (fallback fuzzer)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# arjun (parameter mining)
pip install arjun

# x8 (alt parameter mining, Rust)
cargo install x8    # requires Rust toolchain

# trufflehog (optional, cross-validates JS secret findings)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### 3.4 Pull nuclei templates
```bash
nuclei -update-templates
```

### 3.5 Wordlists (recommended: SecLists)
The repo ships tiny starter wordlists in `wordlists/` so the tool runs out of the box — **replace these with real wordlists for actual engagements**:
```bash
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
# then point config.yaml -> wordlists.content_common / content_php / content_api
# at the relevant SecLists/Discovery/Web-Content/*.txt files
```

---

## 4. Docker (single-command deployment)

```bash
docker build -t reconx:latest .

docker run --rm -it \
  -v $(pwd)/config.yaml:/opt/reconx/config.yaml \
  -v $(pwd)/scope:/opt/reconx/scope \
  -v $(pwd)/data:/opt/reconx/data \
  reconx:latest -d example.com
```

---

## 5. Configuration

Copy and edit `config.yaml`:
```bash
cp config.yaml config.yaml.local   # keep a clean template around
```
Key fields:
- `general.scope_file` — **must** point at a scope file (see `scope/example_scope.txt` for syntax). Nothing is scanned or reported outside this file.
- `general.concurrency` / `general.rate_limit_rps` — tune to avoid WAF bans; start conservative (10–15 rps) against production targets.
- `general.resume` / `general.diff_mode` — resume unfinished scans; diff mode alerts only on newly discovered assets.
- `nuclei.tags` / `nuclei.severity` — keep scoped to `cves,exposures,misconfiguration,default-logins` + `critical,high` to cut noise; widen deliberately.
- `notifications.discord_webhook` / `slack_webhook` — paste webhook URLs to get real-time alerts.
- `api_keys.*` — passive-source API keys. `subfinder` additionally reads `~/.config/subfinder/provider-config.yaml` for most providers — set that up per subfinder's docs for best passive coverage.

---

## 6. Usage

```bash
# Full pipeline against one domain
python main.py -d example.com

# Multiple domains from a file, one per line
python main.py -l targets.txt

# Force full re-scan, ignoring resume state
python main.py -d example.com --force

# Diff mode — only alert on NEW assets since last run
python main.py -d example.com --diff

# Verbose debug logging
python main.py -d example.com -v

# Custom config path
python main.py -d example.com -c /path/to/config.yaml
```

Reports land in `data/results/<target>_report.{json,md,html}`. Scan state lives in `data/reconx.db` (SQLite) — safe to inspect directly with `sqlite3 data/reconx.db`.

---

## 7. Safety / Responsible Use

- **Scope enforcement is mandatory and strict**: every discovered asset is checked against `scope_file` before being persisted, scanned further, or fuzzed. Exclusion rules (`!pattern`) always take precedence.
- **Rate limiting is on by default** (`rate_limit_rps`) to reduce the chance of triggering WAF bans or looking like a DoS.
- Only run against domains/IPs you own or have explicit, written authorization to test (e.g., a bug bounty program's published scope).
- Nuclei is filtered to non-intrusive template classes by default (`cves, exposures, misconfiguration, default-logins`); intrusive/DoS-capable templates are not enabled automatically.

---

## 8. Extending

- Add a new tool: drop a new function in the relevant `modules/*.py` file following the existing `runner.run([...])` pattern, then wire it into `core/orchestrator.py`.
- Add a new phase: create `modules/your_phase.py`, add its name to `PHASES` in `orchestrator.py`, and call it inside `Orchestrator.run_target()` with the same `_should_skip` / `_mark` resume pattern.
- Swap storage backend: `core/database.py` is the only file that touches SQL — repoint it at Postgres via `asyncpg` if you need multi-host shared state.
