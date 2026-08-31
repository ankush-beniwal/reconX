"""
core/database.py
Async SQLite persistence layer.

Responsibilities:
 - Store discovered assets (subdomains, endpoints, ports, findings) keyed by target.
 - Dedup on insert (UNIQUE constraints).
 - Diff mode: return only rows first_seen in *this* run.
 - Resume support: track completed phases per target/run so reruns can skip work.
"""
from __future__ import annotations

import time
from pathlib import Path

import aiosqlite

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(target, subdomain)
);

CREATE TABLE IF NOT EXISTS live_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    tech TEXT,
    cdn TEXT,
    ip TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(target, url)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(target, host, port)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    source TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(target, url)
);

CREATE TABLE IF NOT EXISTS secrets_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    js_url TEXT NOT NULL,
    match_type TEXT NOT NULL,
    snippet TEXT,
    first_seen REAL NOT NULL,
    UNIQUE(target, js_url, match_type, snippet)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    url TEXT NOT NULL,
    template_id TEXT,
    severity TEXT,
    description TEXT,
    first_seen REAL NOT NULL,
    UNIQUE(target, url, template_id)
);

CREATE TABLE IF NOT EXISTS phase_state (
    target TEXT NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL,       -- pending | running | done | failed
    updated_at REAL NOT NULL,
    PRIMARY KEY(target, phase)
);
"""


class ReconDB:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None

    async def connect(self):
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.executescript(SCHEMA)
        await self._conn.commit()
        return self

    async def close(self):
        if self._conn:
            await self._conn.close()

    # ---- generic upsert helper -------------------------------------------------
    async def _upsert(self, table: str, unique_cols: list[str], row: dict) -> bool:
        """Insert row; if it conflicts on unique_cols, update last_seen only.
        Returns True if this was a NEW row (useful for diff-mode alerts)."""
        now = time.time()
        row = {**row, "first_seen": row.get("first_seen", now)}
        if "last_seen" in _table_columns(table):
            row["last_seen"] = now

        cols = list(row.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_list = ", ".join(cols)
        conflict_cols = ", ".join(unique_cols)
        update_cols = [c for c in cols if c not in unique_cols and c != "first_seen"]
        update_clause = ", ".join([f"{c}=excluded.{c}" for c in update_cols]) or "last_seen=excluded.last_seen"

        sql = (
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
            f"ON CONFLICT({conflict_cols}) DO UPDATE SET {update_clause} "
            f"RETURNING (first_seen = ?) as is_new"
        )
        cur = await self._conn.execute(sql, [*row.values(), row["first_seen"]])
        result = await cur.fetchone()
        await self._conn.commit()
        return bool(result[0]) if result else False

    # ---- public insert methods --------------------------------------------------
    async def add_subdomain(self, target: str, subdomain: str, source: str) -> bool:
        return await self._upsert(
            "subdomains", ["target", "subdomain"],
            {"target": target, "subdomain": subdomain, "source": source},
        )

    async def add_live_host(self, target: str, url: str, status_code: int,
                             title: str, tech: str, cdn: str, ip: str) -> bool:
        return await self._upsert(
            "live_hosts", ["target", "url"],
            {"target": target, "url": url, "status_code": status_code,
             "title": title, "tech": tech, "cdn": cdn, "ip": ip},
        )

    async def add_open_port(self, target: str, host: str, port: int) -> bool:
        return await self._upsert(
            "open_ports", ["target", "host", "port"],
            {"target": target, "host": host, "port": port},
        )

    async def add_endpoint(self, target: str, url: str, source: str) -> bool:
        return await self._upsert(
            "endpoints", ["target", "url"],
            {"target": target, "url": url, "source": source},
        )

    async def add_secret_finding(self, target: str, js_url: str, match_type: str, snippet: str) -> bool:
        return await self._upsert(
            "secrets_findings", ["target", "js_url", "match_type", "snippet"],
            {"target": target, "js_url": js_url, "match_type": match_type, "snippet": snippet},
        )

    async def add_vulnerability(self, target: str, url: str, template_id: str,
                                 severity: str, description: str) -> bool:
        return await self._upsert(
            "vulnerabilities", ["target", "url", "template_id"],
            {"target": target, "url": url, "template_id": template_id,
             "severity": severity, "description": description},
        )

    # ---- phase / resume tracking -------------------------------------------------
    async def set_phase_status(self, target: str, phase: str, status: str):
        await self._conn.execute(
            "INSERT INTO phase_state(target, phase, status, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(target, phase) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
            (target, phase, status, time.time()),
        )
        await self._conn.commit()

    async def get_phase_status(self, target: str, phase: str) -> str | None:
        cur = await self._conn.execute(
            "SELECT status FROM phase_state WHERE target=? AND phase=?", (target, phase)
        )
        row = await cur.fetchone()
        return row[0] if row else None

    # ---- diff / query helpers -----------------------------------------------------
    async def new_since(self, table: str, target: str, since_ts: float) -> list[dict]:
        cur = await self._conn.execute(
            f"SELECT * FROM {table} WHERE target=? AND first_seen >= ?", (target, since_ts)
        )
        cols = [d[0] for d in cur.description]
        rows = await cur.fetchall()
        return [dict(zip(cols, r)) for r in rows]

    async def all_for_target(self, table: str, target: str) -> list[dict]:
        cur = await self._conn.execute(f"SELECT * FROM {table} WHERE target=?", (target,))
        cols = [d[0] for d in cur.description]
        rows = await cur.fetchall()
        return [dict(zip(cols, r)) for r in rows]

    async def start_run(self, target: str) -> int:
        cur = await self._conn.execute(
            "INSERT INTO runs(target, started_at) VALUES (?, ?)", (target, time.time())
        )
        await self._conn.commit()
        return cur.lastrowid

    async def finish_run(self, run_id: int):
        await self._conn.execute(
            "UPDATE runs SET finished_at=? WHERE run_id=?", (time.time(), run_id)
        )
        await self._conn.commit()


def _table_columns(table: str) -> set[str]:
    # Static map matching SCHEMA above (avoids an extra DB round trip on hot path).
    common = {"first_seen", "last_seen"}
    no_last_seen = {"secrets_findings", "vulnerabilities", "phase_state", "runs"}
    if table in no_last_seen:
        return common - {"last_seen"}
    return common
