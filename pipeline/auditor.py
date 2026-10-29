"""
pipeline/auditor.py: Stage 2 post-inference closed-domain gatekeeper.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from core.bounds import SymmetricalContract
from core.validator import InvariantValidator
from pipeline.compiler import PromptCompiler
from pipeline.quarantine import QuarantineRouter


class ModelAuditor:
    """Extracts output records and verifies grounding against registered source digests."""

    def __init__(
        self,
        contract: Optional[SymmetricalContract] = None,
        validator: Optional[InvariantValidator] = None,
        quarantine: Optional[QuarantineRouter] = None,
    ):
        self.contract = contract or SymmetricalContract.standard_telemetry_tuple()
        self.validator = validator or InvariantValidator(contract=self.contract)
        self.quarantine = quarantine or QuarantineRouter(Path("./quarantine"))
        self.audited_records: List[Dict[str, Any]] = []

    def audit_response(self, raw_response: str, start_byte_offset: int = 0) -> List[Dict[str, Any]]:
        cleaned = raw_response.strip()
        md_pattern = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", re.MULTILINE)
        match = md_pattern.search(cleaned)
        json_target = match.group(1).strip() if match else cleaned

        records_to_evaluate: List[Tuple[Any, int]] = []
        if json_target.startswith("[") and json_target.endswith("]"):
            try:
                data_list = json.loads(json_target)
                if isinstance(data_list, list):
                    for idx, item in enumerate(data_list):
                        records_to_evaluate.append((item, start_byte_offset + idx))
            except json.JSONDecodeError as err:
                self.quarantine.route_to_quarantine(
                    payload=raw_response,
                    byte_offset=start_byte_offset,
                    failed_rule_index=300,
                    rule_name="AUDITOR_JSON_ARRAY_DECODE_FAIL",
                    error_message=str(err),
                )
                return []
        else:
            compiler = PromptCompiler(self.contract, self.validator, self.quarantine)
            return compiler.compile_ingress_block(json_target, start_byte_offset)

        valid_audited: List[Dict[str, Any]] = []
        for item, offset in records_to_evaluate:
            if not isinstance(item, dict):
                self.quarantine.route_to_quarantine(
                    payload=str(item),
                    byte_offset=offset,
                    failed_rule_index=301,
                    rule_name="AUDITOR_ITEM_NOT_DICT",
                    error_message=f"Extracted item is not a dictionary tuple: {type(item).__name__}",
                )
                continue

            is_valid, rule_idx, rule_name, err_msg = self.validator.validate_record(item)
            if not is_valid:
                self.quarantine.route_to_quarantine(
                    payload=item,
                    byte_offset=offset,
                    failed_rule_index=rule_idx,
                    rule_name=rule_name,
                    error_message=err_msg,
                )
                continue

            valid_audited.append(item)
            self.audited_records.append(item)

        return valid_audited