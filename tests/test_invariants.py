"""
tests/test_invariants.py: Fuzz testing, quarantine replaying, and sentinel runtime guards.
"""

import json
from pathlib import Path
import shutil
import sys
import threading
import time
import unittest

from core.bounds import (
    EXIT_SUCCESS,
    ProcessTimeoutExpired,
    SecurityBoundaryViolation,
    SymmetricalContract,
)
from core.validator import InvariantValidator
from pipeline.auditor import ModelAuditor
from pipeline.compiler import PromptCompiler
from pipeline.quarantine import QuarantineReplayHarness, QuarantineRouter
from runtime.path_guard import PathSanitizer
from runtime.process_guard import bounded_subprocess_run
from runtime.sentinel import BoundedStreamSentinel


class TestInvariants(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path("./.test_invariants_scratch").resolve()
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir = self.test_dir / "quarantine"
        self.quarantine = QuarantineRouter(self.quarantine_dir)
        self.contract = SymmetricalContract.standard_telemetry_tuple()
        self.validator = InvariantValidator(self.contract)
        self.validator.register_grounded_source("VERIFIED_DOC_1")
        self.validator.register_grounded_source("DOC_TELEMETRY_A")
        self.validator.register_grounded_source("DOC_TELEMETRY_B")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_path_traversal_fail_closed(self):
        sanitizer = PathSanitizer(self.test_dir)
        with self.assertRaises(SecurityBoundaryViolation):
            sanitizer.validate_safe_path("../../../outside_root.txt")

    def test_subprocess_timeout_fail_closed(self):
        with self.assertRaises(ProcessTimeoutExpired):
            bounded_subprocess_run(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout_seconds=0.2,
                fail_closed=True,
            )

    def test_ungrounded_citation_quarantine(self):
        compiler = PromptCompiler(self.contract, self.validator, self.quarantine)
        raw_payload = '{"timestamp": "2026-10-28 04:00:00", "entity": "NODE_1", "metric": 10.0, "source_ref": "GHOST_CITATION"}'
        records = compiler.compile_ingress_block(raw_payload)
        self.assertEqual(len(records), 0)
        self.assertEqual(self.quarantine.quarantined_count, 1)

    def test_auditor_markdown_strip_and_schema_rejection(self):
        auditor = ModelAuditor(self.contract, self.validator, self.quarantine)
        response = """
        Analysis extracted:
        ```json
        [
          {"timestamp": "2026-10-28 04:00:00", "entity": "SENSOR_1", "metric": 12.5, "source_ref": "VERIFIED_DOC_1"},
          {"timestamp": "2026-10-28 04:00:00", "entity": "SENSOR_2", "metric": "corrupted", "source_ref": "UNKNOWN_REF"}
        ]
        ```
        """
        audited = auditor.audit_response(response)
        self.assertEqual(len(audited), 1)
        self.assertEqual(audited[0]["entity"], "SENSOR_1")
        self.assertEqual(self.quarantine.quarantined_count, 1)

    def test_quarantine_replay_and_field_stripping(self):
        bad_payload = {
            "timestamp": "2026-10-28 04:00:00",
            "entity": "NODE_TEST",
            "metric": 50.0,
            "source_ref": "VERIFIED_DOC_1",
            "unauthorized_extra_key": "MALICIOUS_INJECTION"
        }
        self.compiler = PromptCompiler(self.contract, self.validator, self.quarantine)
        self.compiler.compile_ingress_block(json.dumps(bad_payload))
        self.assertEqual(self.quarantine.quarantined_count, 1)

        replay_harness = QuarantineReplayHarness(self.quarantine)
        dead_letters = replay_harness.load_dead_letter_records()
        self.assertEqual(len(dead_letters), 1)

        result_fail = replay_harness.replay_single_record(
            dead_letters[0],
            validation_fn=self.validator.validate_record
        )
        self.assertFalse(result_fail.replayed_success)
        self.assertIn("SCHEMA_EXCESS_KEYS", result_fail.failure_reason)

        transformer = lambda payload: QuarantineReplayHarness.strip_fields(
            payload, ["unauthorized_extra_key"]
        )
        result_pass = replay_harness.replay_single_record(
            dead_letters[0],
            validation_fn=self.validator.validate_record,
            transformer_fn=transformer
        )
        self.assertTrue(result_pass.replayed_success)
        self.assertIsNotNone(result_pass.remediated_payload)
        self.assertNotIn("unauthorized_extra_key", result_pass.remediated_payload)

    def test_sentinel_tearing_defense_and_record_ceiling(self):
        live_log = self.test_dir / "live_feed.log"
        accepted_out = self.test_dir / "accepted.jsonl"
        pulse_file = self.test_dir / "pulse.txt"

        part_1 = b'{"timestamp": "2026-10-28T04:15:00Z", "entity": "CORE_NODE_01"'
        with open(live_log, "wb") as fh:
            fh.write(part_1)
            fh.flush()

        sentinel = BoundedStreamSentinel(
            workspace_root=self.test_dir,
            input_log=live_log,
            accepted_egress=accepted_out,
            quarantine_dir=self.quarantine_dir,
            grounded_sources=["DOC_TELEMETRY_A", "DOC_TELEMETRY_B"],
            max_runtime_seconds=5.0,
            max_records=2,
            poll_interval_seconds=0.05,
        )

        def _delayed_writer():
            time.sleep(0.15)
            self.assertEqual(sentinel.byte_cursor, 0)
            self.assertEqual(sentinel.accepted_count, 0)

            part_2 = b', "metric": 48.2, "source_ref": "DOC_TELEMETRY_A"}\n'
            line_2 = b"2026-10-28 04:15:30 | SPARTAN_IPC_BUS | 100.0 | DOC_TELEMETRY_B\n"
            with open(live_log, "ab") as fh:
                fh.write(part_2)
                fh.flush()
                time.sleep(0.10)
                fh.write(line_2)
                fh.flush()

        writer_thread = threading.Thread(target=_delayed_writer, daemon=True)
        writer_thread.start()

        exit_code = sentinel.run_bounded_loop()
        writer_thread.join(timeout=2.0)

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertEqual(sentinel.accepted_count, 2)
        self.assertEqual(sentinel.quarantine.quarantined_count, 0)
        self.assertTrue(pulse_file.exists())

        with open(pulse_file, "r", encoding="utf-8") as pf:
            pulse_data = json.load(pf)

        self.assertEqual(pulse_data["status"], "HALT_RECORD_CEILING_REACHED")
        self.assertEqual(pulse_data["accepted_count"], 2)
        self.assertEqual(pulse_data["quarantined_count"], 0)

    def test_sentinel_time_ceiling_and_ungrounded_quarantine(self):
        live_log = self.test_dir / "live_feed_time.log"
        accepted_out = self.test_dir / "accepted_time.jsonl"
        pulse_file = self.test_dir / "pulse.txt"

        ungrounded_payload = (
            '{"timestamp": "2026-10-28T04:16:30Z", "entity": "GHOST_NODE_99", '
            '"metric": 0.0, "source_ref": "PHANTOM_CITATION_GHOST"}\n'
        )
        with open(live_log, "wb") as fh:
            fh.write(ungrounded_payload.encode("utf-8"))
            fh.flush()

        sentinel = BoundedStreamSentinel(
            workspace_root=self.test_dir,
            input_log=live_log,
            accepted_egress=accepted_out,
            quarantine_dir=self.quarantine_dir,
            grounded_sources=["DOC_TELEMETRY_A", "DOC_TELEMETRY_B"],
            max_runtime_seconds=0.1,
            max_records=10,
            poll_interval_seconds=0.01,
        )

        exit_code = sentinel.run_bounded_loop()

        self.assertEqual(exit_code, EXIT_SUCCESS)
        self.assertEqual(sentinel.accepted_count, 0)
        self.assertEqual(sentinel.quarantine.quarantined_count, 1)
        self.assertTrue(pulse_file.exists())

        with open(pulse_file, "r", encoding="utf-8") as pf:
            pulse_data = json.load(pf)

        self.assertEqual(pulse_data["status"], "HALT_TIME_CEILING_REACHED")
        self.assertEqual(pulse_data["accepted_count"], 0)
        self.assertEqual(pulse_data["quarantined_count"], 1)


if __name__ == "__main__":
    unittest.main()