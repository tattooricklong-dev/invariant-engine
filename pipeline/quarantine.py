"""
pipeline/quarantine.py: Dead-letter failure router & quarantine logger with replay harness.
Standard Library Only: json, dataclasses, pathlib, time, datetime, typing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
from core.hasher import CanonicalHasher


@dataclass(frozen=True)
class QuarantineRecord:
    """Immutable forensic audit record for malformed payloads."""
    payload: str
    byte_offset: int
    timestamp_utc: str
    failed_rule_index: int
    rule_name: str
    error_message: str
    payload_sha256: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


class QuarantineRouter:
    """Dead-letter quarantine router preventing heuristic patching."""

    def __init__(self, egress_dir: Union[str, Path], log_file_name: str = "quarantine.log"):
        self.egress_dir = Path(egress_dir).resolve()
        self.egress_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.egress_dir / log_file_name
        self._quarantined_count = 0

    @property
    def quarantined_count(self) -> int:
        return self._quarantined_count

    def route_to_quarantine(
        self,
        payload: Union[str, bytes, Dict[str, Any]],
        byte_offset: int,
        failed_rule_index: int,
        rule_name: str,
        error_message: str,
    ) -> QuarantineRecord:
        if isinstance(payload, bytes):
            raw_str = payload.decode("utf-8", errors="replace")
        elif isinstance(payload, str):
            raw_str = payload
        else:
            raw_str = json.dumps(payload, ensure_ascii=False)

        timestamp_utc = datetime.now(timezone.utc).isoformat()
        digest = CanonicalHasher.digest(raw_str)

        record = QuarantineRecord(
            payload=raw_str,
            byte_offset=byte_offset,
            timestamp_utc=timestamp_utc,
            failed_rule_index=failed_rule_index,
            rule_name=rule_name,
            error_message=error_message,
            payload_sha256=digest,
        )

        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")

        safe_hash = digest[:16]
        dead_letter_file = self.egress_dir / f"dead_letter_{int(time.time())}_{safe_hash}.json"
        with open(dead_letter_file, "w", encoding="utf-8") as fh:
            fh.write(record.to_json())

        self._quarantined_count += 1
        return record


@dataclass(frozen=True)
class ReplayResult:
    """Forensic report documenting the replay of a quarantined dead-letter record."""
    original_sha256: str
    replayed_success: bool
    remediated_payload: Optional[Dict[str, Any]]
    failure_reason: str = ""


class QuarantineReplayHarness:
    """Forensic replay engine for non-destructive re-evaluation of dead-letters."""

    def __init__(self, quarantine_router: QuarantineRouter):
        self.router = quarantine_router

    def load_dead_letter_records(self) -> List[QuarantineRecord]:
        if not self.router.log_file.exists():
            return []

        records: List[QuarantineRecord] = []
        with open(self.router.log_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    data = json.loads(line_str)
                    records.append(QuarantineRecord(**data))
                except (json.JSONDecodeError, TypeError):
                    continue
        return records

    @staticmethod
    def strip_fields(payload_dict: Dict[str, Any], fields_to_remove: Sequence[str]) -> Dict[str, Any]:
        remove_set = set(fields_to_remove)
        return {k: v for k, v in payload_dict.items() if k not in remove_set}

    def replay_single_record(
        self,
        record: QuarantineRecord,
        validation_fn: Callable[[Dict[str, Any]], Tuple[bool, int, str, str]],
        transformer_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> ReplayResult:
        try:
            parsed = json.loads(record.payload)
            if not isinstance(parsed, dict):
                return ReplayResult(
                    original_sha256=record.payload_sha256,
                    replayed_success=False,
                    remediated_payload=None,
                    failure_reason=f"Payload is not a dict: {type(parsed).__name__}",
                )
        except json.JSONDecodeError:
            return ReplayResult(
                original_sha256=record.payload_sha256,
                replayed_success=False,
                remediated_payload=None,
                failure_reason="Raw payload is non-JSON or unparseable text",
            )

        target_payload = transformer_fn(parsed) if transformer_fn else parsed
        is_valid, rule_idx, rule_name, err_msg = validation_fn(target_payload)
        if is_valid:
            return ReplayResult(
                original_sha256=record.payload_sha256,
                replayed_success=True,
                remediated_payload=target_payload,
                failure_reason="",
            )

        return ReplayResult(
            original_sha256=record.payload_sha256,
            replayed_success=False,
            remediated_payload=target_payload,
            failure_reason=f"Rule {rule_idx} [{rule_name}]: {err_msg}",
        )

    def batch_replay(
        self,
        validation_fn: Callable[[Dict[str, Any]], Tuple[bool, int, str, str]],
        transformer_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> List[ReplayResult]:
        records = self.load_dead_letter_records()
        return [
            self.replay_single_record(rec, validation_fn, transformer_fn)
            for rec in records
        ]