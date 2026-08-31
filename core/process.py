"""
core/process.py
Clean async subprocess execution wrapper shared by every module.

Provides:
 - Global semaphore-based concurrency cap.
 - Token-bucket rate limiter (requests/sec) to avoid WAF bans / IP blocks.
 - Hard per-call timeout with graceful process termination.
 - Structured result object (stdout/stderr/returncode/duration).
"""
from __future__ import annotations

import asyncio
import shutil
import time
from dataclasses import dataclass

from core.logger import get_logger

log = get_logger(__name__)


@dataclass
class ProcResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class RateLimiter:
    """Simple async token bucket. call `await limiter.acquire()` before each op."""

    def __init__(self, rate_per_sec: float):
        self.rate = max(rate_per_sec, 0.1)
        self._tokens = self.rate
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class ProcessRunner:
    """Shared runner: one instance per orchestrator run, injected into every module."""

    def __init__(self, concurrency: int = 25, rate_limit_rps: float = 15,
                 default_timeout: int = 600):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.rate_limiter = RateLimiter(rate_limit_rps)
        self.default_timeout = default_timeout

    @staticmethod
    def is_available(binary: str) -> bool:
        return shutil.which(binary) is not None

    async def run(self, cmd: list[str], timeout: int | None = None,
                   input_data: str | None = None, cwd: str | None = None) -> ProcResult:
        binary = cmd[0]
        if not self.is_available(binary):
            log.warning(f"[yellow]Tool not found on PATH:[/yellow] {binary} — skipping call.")
            return ProcResult(cmd=cmd, returncode=127, stdout="", stderr=f"{binary} not found", duration=0.0)

        timeout = timeout or self.default_timeout
        async with self.semaphore:
            await self.rate_limiter.acquire()
            start = time.monotonic()
            timed_out = False
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE if input_data else None,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(input_data.encode() if input_data else None),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    timed_out = True
                    proc.kill()
                    await proc.wait()
                    stdout, stderr = b"", b"process killed after timeout"
            except FileNotFoundError as e:
                return ProcResult(cmd=cmd, returncode=127, stdout="", stderr=str(e), duration=0.0)

            duration = time.monotonic() - start
            result = ProcResult(
                cmd=cmd,
                returncode=proc.returncode if not timed_out else -1,
                stdout=stdout.decode(errors="ignore"),
                stderr=stderr.decode(errors="ignore"),
                duration=duration,
                timed_out=timed_out,
            )
            if not result.ok:
                log.debug(f"[red]Command failed[/red] ({' '.join(cmd[:3])}...): rc={result.returncode} "
                          f"timed_out={timed_out} stderr={result.stderr[:200]}")
            return result

    async def run_many(self, commands: list[list[str]], timeout: int | None = None) -> list[ProcResult]:
        return await asyncio.gather(*[self.run(c, timeout=timeout) for c in commands])
