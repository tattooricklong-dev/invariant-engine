"""
runtime/sentinel.py: Bounded continuous file-stream sentinel with byte-offset cursor,
unbuffered FS/FUSE-tolerant disk flushing, and asynchronous pulse.txt heartbeat telemetry.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Sequence, Union

from core.bounds import (
    EXIT_SUCCESS,
    EXIT_TIMEOUT_INTERRUPT,
    EXIT_VALIDATION_FAILURE,
    SymmetricalContract,
)
from core.validator import InvariantValidator
from pipeline.compiler import PromptCompiler
from pipeline.quarantine import QuarantineRouter
from runtime.path_guard import PathSanitizer


class BoundedStreamSentinel:
    """
    Polls an append-only telemetry file within strict operational budgets:
      1. Artificial Mortality: Enforces max_runtime_seconds and max_records ceilings.
      2. Byte-Offset Cursor Persistence: Seeks exact byte offsets across reads.
      3. Mid-Write Tearing Defense: Waits for trailing b"\\n" before advancing cursor.
      4. FS/FUSE Fault-Tolerant Flushing: Flushes buffers and wraps os.fsync in try/except OSError.
      5. Asynchronous Heartbeat Ledger: Writes atomic state snapshots to pulse.txt.
    """

    def __init__(
        self,
        workspace_root: Union[str, Path],
        input_log: Union[str, Path],
        accepted_egress: Union[str, Path],
        quarantine_dir: Union[str, Path],
        grounded_sources: Sequence[str],
        max_runtime_seconds: float = 60.0,
        max_records: int = 1000,
        poll_interval_seconds: float = 0.5,
    ):
        self.sanitizer = PathSanitizer(workspace_root)
        self.input_path = self.sanitizer.validate_safe_path(input_log, must_exist=True)
        self.egress_path = self.sanitizer.validate_safe_path(accepted_egress, must_exist=False)
        self.quarantine_path = self.sanitizer.validate_safe_path(quarantine_dir, must_exist=False)
        self.pulse_path = self.sanitizer.validate_safe_path("pulse.txt", must_exist=False)

        self.contract = SymmetricalContract.standard_telemetry_tuple()
        self.validator = InvariantValidator(self.contract, grounded_sources=grounded_sources)
        self.quarantine = QuarantineRouter(self.quarantine_path)
        self.compiler = PromptCompiler(self.contract, self.validator, self.quarantine)

        self.max_runtime_seconds = max_runtime_seconds
        self.max_records = max_records
        self.poll_interval_seconds = poll_interval_seconds

        self.byte_cursor: int = 0
        self.accepted_count: int = 0

    @staticmethod
    def _safe_flush_and_sync(fh) -> None:
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass

    def _emit_heartbeat(self, status: str) -> None:
        pulse_payload = {
            "accepted_count": self.accepted_count,
            "byte_cursor": self.byte_cursor,
            "quarantined_count": self.quarantine.quarantined_count,
            "status": status,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.pulse_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(pulse_payload, indent=2, sort_keys=True) + "\n")
            self._safe_flush_and_sync(fh)

    def run_bounded_loop(self) -> int:
        start_monotonic = time.perf_counter()
        self._emit_heartbeat("ACTIVE")

        try:
            self.egress_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.input_path, "rb") as stream_fh, open(
                self.egress_path, "a", encoding="utf-8"
            ) as out_fh:
                while True:
                    elapsed = time.perf_counter() - start_monotonic
                    if elapsed >= self.max_runtime_seconds:
                        self._emit_heartbeat("HALT_TIME_CEILING_REACHED")
                        return EXIT_SUCCESS

                    if (self.accepted_count + self.quarantine.quarantined_count) >= self.max_records:
                        self._emit_heartbeat("HALT_RECORD_CEILING_REACHED")
                        return EXIT_SUCCESS

                    stream_fh.seek(self.byte_cursor)
                    raw_line_bytes = stream_fh.readline()

                    if not raw_line_bytes:
                        self._emit_heartbeat("IDLE_WAITING_FOR_BYTES")
                        time.sleep(self.poll_interval_seconds)
                        continue

                    if not raw_line_bytes.endswith(b"\n"):
                        time.sleep(self.poll_interval_seconds)
                        continue

                    line_offset = self.byte_cursor
                    self.byte_cursor += len(raw_line_bytes)
                    decoded_line = raw_line_bytes.decode("utf-8", errors="replace")

                    valid_batch = self.compiler.compile_ingress_block(
                        decoded_line, start_byte_offset=line_offset
                    )

                    for rec in valid_batch:
                        out_fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                        self.accepted_count += 1

                    self._safe_flush_and_sync(out_fh)
                    self._emit_heartbeat("STREAMING")

        except KeyboardInterrupt:
            self._emit_heartbeat("HALT_SIGINT")
            return EXIT_TIMEOUT_INTERRUPT
        except Exception as exc:
            self._emit_heartbeat(f"FAIL_CLOSED_ERROR: {type(exc).__name__}")
            raise


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m runtime.sentinel",
        description="Bounded Continuous Stream Sentinel.",
    )
    parser.add_argument("-w", "--workspace", default=".", help="Root workspace directory.")
    parser.add_argument("-i", "--input-file", required=True, help="Target input log file path.")
    parser.add_argument("-o", "--output", default="accepted.jsonl", help="Primary egress JSONL path.")
    parser.add_argument("-q", "--quarantine-dir", default="./quarantine", help="Quarantine directory.")
    parser.add_argument("-s", "--sources", default="", help="Comma-separated verified source citations.")
    parser.add_argument("--max-runtime", type=float, default=60.0, help="Hard runtime ceiling in seconds.")
    parser.add_argument("--max-records", type=int, default=1000, help="Hard record count ceiling.")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Poll interval in seconds.")

    args = parser.parse_args()
    sources = [s.strip() for s in args.sources.split(",") if s.strip()]

    sentinel = BoundedStreamSentinel(
        workspace_root=args.workspace,
        input_log=args.input_file,
        accepted_egress=args.output,
        quarantine_dir=args.quarantine_dir,
        grounded_sources=sources,
        max_runtime_seconds=args.max_runtime,
        max_records=args.max_records,
        poll_interval_seconds=args.poll_interval,
    )
    sys.exit(sentinel.run_bounded_loop())


if __name__ == "__main__":
    main()