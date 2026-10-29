"""
core/validator.py: Schema verification and grounded citation checks.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Set, Tuple
from core.bounds import SymmetricalContract


class InvariantValidator:
    """Validates records against contract schemas and grounded source registries."""

    def __init__(
        self,
        contract: Optional[SymmetricalContract] = None,
        grounded_sources: Optional[Sequence[str]] = None,
    ):
        self.contract = contract or SymmetricalContract.standard_telemetry_tuple()
        self.grounded_sources: Set[str] = set(grounded_sources or [])

    def register_grounded_source(self, source_ref: str) -> None:
        self.grounded_sources.add(source_ref)

    def validate_record(self, record: Dict[str, Any]) -> Tuple[bool, int, str, str]:
        is_valid, rule_idx, rule_name, err_msg = self.contract.validate_record_dict(record)
        if not is_valid:
            return False, rule_idx, rule_name, err_msg

        if "source_ref" in record and self.grounded_sources:
            ref = str(record["source_ref"])
            if ref not in self.grounded_sources:
                return (
                    False,
                    200,
                    "UNGROUNDED_SOURCE_CITATION",
                    f"Source citation '{ref}' is not present in verified source registry",
                )

        return True, 0, "SUCCESS", ""