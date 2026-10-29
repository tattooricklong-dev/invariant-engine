"""
runtime/process_guard.py: Subprocess timeouts, buffer drains, clean exits.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import time
from typing import Dict, List, Optional, Sequence, Union
from core.bounds import ProcessTimeoutExpired, SubprocessExecutionError


@dataclass(frozen=True)
class SubprocessResult:
    """Telemetry report for bounded subprocess execution."""
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    execution_time_seconds: float
    timed_out: bool = False


def bounded_subprocess_run(
    cmd: Sequence[str],
    timeout_seconds: float = 10.0,
    cwd: Optional[Union[str, Path]] = None,
    env: Optional[Dict[str, str]] = None,
    fail_closed: bool = True,
) -> SubprocessResult:
    cmd_list = [str(c) for c in cmd]
    start_time = time.perf_counter()
    proc: Optional[subprocess.Popen] = None
    stdout_data = ""
    stderr_data = ""
    timed_out = False

    try:
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
            env=env or os.environ.copy(),
        )

        try:
            stdout_data, stderr_data = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            rem_stdout, rem_stderr = proc.communicate()
            stdout_data = (stdout_data or "") + (rem_stdout or "")
            stderr_data = (stderr_data or "") + (rem_stderr or "")

            if fail_closed:
                raise ProcessTimeoutExpired(
                    f"Subprocess '{cmd_list[0]}' exceeded hard timeout of {timeout_seconds}s. "
                    f"Process killed. Stderr: {stderr_data.strip()}"
                )

    except Exception as exc:
        if isinstance(exc, ProcessTimeoutExpired):
            raise
        if proc and proc.poll() is None:
            proc.kill()
        if fail_closed:
            raise SubprocessExecutionError(f"Subprocess spawn/run error: {exc}") from exc

    duration = time.perf_counter() - start_time
    rc = proc.returncode if proc else -1

    result = SubprocessResult(
        command=cmd_list,
        returncode=rc,
        stdout=stdout_data or "",
        stderr=stderr_data or "",
        execution_time_seconds=round(duration, 4),
        timed_out=timed_out,
    )

    if fail_closed and rc != 0:
        raise SubprocessExecutionError(
            f"Command {cmd_list} failed with exit code {rc}.\n"
            f"Telemetry Stderr: {stderr_data.strip()}\n"
            f"Telemetry Stdout: {stdout_data.strip()}"
        )

    return result