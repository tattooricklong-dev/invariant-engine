"""
pipeline/compiler.py: Stage 1 Ingress normalizer & prompt compiler.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from core.bounds import SymmetricalContract
from core.validator import InvariantValidator
from pipeline.quarantine import QuarantineRouter


class PromptCompiler:
    """Ingests raw tabular or JSON data and validates compliance with symmetrical schemas."""

    def __init__(
        self,
        contract: Optional[SymmetricalContract] = None,
        validator: Optional[InvariantValidator] = None,
        quarantine: Optional[QuarantineRouter] = None,
    ):
        self.contract = contract or SymmetricalContract.standard_telemetry_tuple()
        self.validator = validator or InvariantValidator(contract=self.contract)
        self.quarantine = quarantine or QuarantineRouter(Path("./quarantine"))
        self.ingested_records: List[Dict[str, Any]] = []

    def compile_ingress_block(self, raw_text: str, start_byte_offset: int = 0) -> List[Dict[str, Any]]:
        valid_batch: List[Dict[str, Any]] = []
        lines = raw_text.splitlines(keepends=True)
        current_offset = start_byte_offset

        for line in lines:
            line_bytes = line.encode("utf-8")
            line_str = line.strip()
            line_offset = current_offset
            current_offset += len(line_bytes)

            if not line_str or line_str.startswith("#"):
                continue

            parsed_record: Optional[Dict[str, Any]] = None

            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    parsed_record = json.loads(line_str)
                except json.JSONDecodeError as err:
                    self.quarantine.route_to_quarantine(
                        payload=line_str,
                        byte_offset=line_offset,
                        failed_rule_index=100,
                        rule_name="JSON_DECODE_ERROR",
                        error_message=str(err),
                    )
                    continue
            else:
                delim = "|" if "|" in line_str else ("," if "," in line_str else None)
                if delim:
                    tokens = [t.strip() for t in line_str.split(delim)]
                    if len(tokens) == len(self.contract.fields):
                        record_dict = {}
                        for spec, tok in zip(self.contract.fields, tokens):
                            if spec.expected_type is float:
                                try:
                                    record_dict[spec.name] = float(tok)
                                except ValueError:
                                    record_dict[spec.name] = tok
                            elif spec.expected_type is int:
                                try:
                                    record_dict[spec.name] = int(tok)
                                except ValueError:
                                    record_dict[spec.name] = tok
                            else:
                                record_dict[spec.name] = tok
                        parsed_record = record_dict
                    else:
                        self.quarantine.route_to_quarantine(
                            payload=line_str,
                            byte_offset=line_offset,
                            failed_rule_index=101,
                            rule_name="TABULAR_ARITY_MISMATCH",
                            error_message=f"Expected {len(self.contract.fields)} tokens, found {len(tokens)}",
                        )
                        continue
                else:
                    self.quarantine.route_to_quarantine(
                        payload=line_str,
                        byte_offset=line_offset,
                        failed_rule_index=102,
                        rule_name="UNKNOWN_LINE_STRUCTURE",
                        error_message="Line is neither valid JSON nor delimited tuple",
                    )
                    continue

            if parsed_record:
                is_valid, rule_idx, rule_name, err_msg = self.validator.validate_record(parsed_record)
                if not is_valid:
                    self.quarantine.route_to_quarantine(
                        payload=parsed_record,
                        byte_offset=line_offset,
                        failed_rule_index=rule_idx,
                        rule_name=rule_name,
                        error_message=err_msg,
                    )
                    continue

                valid_batch.append(parsed_record)
                self.ingested_records.append(parsed_record)

        return valid_batch