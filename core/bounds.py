"""
core/bounds.py: Immutable text prompts, sentinels, and schema specifications.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILURE = 1
EXIT_SUBPROCESS_FAILURE = 2
EXIT_TIMEOUT_INTERRUPT = 130


class BaremetalEngineError(Exception):
    """Base exception for all baremetal_engine invariant failures."""


class SecurityBoundaryViolation(BaremetalEngineError):
    """Raised when an operation breaches directory or path isolation perimeters."""


class SchemaContractViolation(BaremetalEngineError):
    """Raised when a data payload fails strict schema invariant checks."""


class SubprocessExecutionError(BaremetalEngineError):
    """Raised when a monitored subprocess fails or returns a non-zero code."""


class ProcessTimeoutExpired(BaremetalEngineError):
    """Raised when a subprocess exceeds its hard operational time ceiling."""


@dataclass(frozen=True)
class FieldSpec:
    """Specification of an immutable schema field."""
    name: str
    expected_type: type
    required: bool = True
    regex_pattern: Optional[str] = None
    description: str = ""


@dataclass(frozen=True)
class SymmetricalContract:
    """
    Defines the dual-purpose symmetrical schema contract for ingress
    and model extraction auditing.
    """
    fields: Tuple[FieldSpec, ...]
    contract_name: str = "StandardTelemetryTuple"

    @classmethod
    def standard_telemetry_tuple(cls) -> "SymmetricalContract":
        return cls(
            fields=(
                FieldSpec("timestamp", str, True, r"^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}", "ISO-8601 timestamp"),
                FieldSpec("entity", str, True, None, "Target component or record identifier"),
                FieldSpec("metric", (int, float, str), True, None, "Observed telemetry value or metric"),
                FieldSpec("source_ref", str, True, None, "Grounded citation hash or document pointer"),
            ),
            contract_name="StandardTelemetryTuple",
        )

    def generate_prompt_contract(self) -> str:
        fields_desc = [
            f'"{f.name}": <{f.expected_type.__name__ if isinstance(f.expected_type, type) else "val"} - {f.description}>'
            for f in self.fields
        ]
        field_names = [f.name for f in self.fields]
        return (
            f"=== SYMMETRIC EXTRACTION CONTRACT: {self.contract_name} ===\n"
            f"You MUST emit findings ONLY as a JSON list of objects matching these EXACT keys:\n"
            f"[{', '.join(field_names)}]\n\n"
            "SCHEMA SPECIFICATION:\n"
            "[\n  {\n    " + ",\n    ".join(fields_desc) + "\n  }\n]\n"
            "STRICT COMPLIANCE DIRECTIVE: Do not include markdown preamble, commentary, or extraneous keys.\n"
            "Any missing field, altered key name, or untyped tuple will trigger immediate quarantine rejection."
        )

    def validate_record_dict(self, record: Dict[str, Any]) -> Tuple[bool, int, str, str]:
        if not isinstance(record, dict):
            return False, 0, "TYPE_CHECK", f"Expected dictionary, received {type(record).__name__}"

        field_map = {f.name: f for f in self.fields}
        record_keys = set(record.keys())
        expected_keys = set(field_map.keys())

        extra_keys = record_keys - expected_keys
        if extra_keys:
            return False, 1, "SCHEMA_EXCESS_KEYS", f"Unrecognized keys detected: {sorted(list(extra_keys))}"

        for idx, spec in enumerate(self.fields, start=2):
            if spec.name not in record:
                if spec.required:
                    return False, idx, "MISSING_REQUIRED_FIELD", f"Missing required field: '{spec.name}'"
                continue

            val = record[spec.name]

            if isinstance(spec.expected_type, tuple):
                if not isinstance(val, spec.expected_type):
                    return (
                        False,
                        idx,
                        "TYPE_MISMATCH",
                        f"Field '{spec.name}' invalid type {type(val).__name__}; expected {spec.expected_type}",
                    )
            elif not isinstance(val, spec.expected_type):
                if spec.expected_type is float and isinstance(val, (int, float)):
                    pass
                else:
                    return (
                        False,
                        idx,
                        "TYPE_MISMATCH",
                        f"Field '{spec.name}' invalid type {type(val).__name__}; expected {spec.expected_type.__name__}",
                    )

            if spec.regex_pattern and isinstance(val, str):
                if not re.search(spec.regex_pattern, val):
                    return (
                        False,
                        idx,
                        "REGEX_PATTERN_MISMATCH",
                        f"Field '{spec.name}' failed pattern check: {spec.regex_pattern}",
                    )

        return True, 0, "SUCCESS", ""