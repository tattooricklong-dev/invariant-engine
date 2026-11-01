#!/usr/bin/env python3
import unittest
from codifier_engine import (
    CodifierEngine, FrictionTier, DirectiveContract,
    BoundedExecutionSubstrate, ContractValidationError,
    EXIT_SUCCESS, EXIT_VALIDATION_FAILURE, EXIT_RESOURCE_EXHAUSTION,
    MAX_CONCEPT_LENGTH
)

class TestCodifierEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CodifierEngine(grip_level=5.0)

    def test_tier_1_assimilate_subset_invariant(self):
        self.engine.set_grip(1.5)
        c = self.engine.compile_concept('IPC Pipes and Filesystem Streams')
        self.assertEqual(c.tier, 'ASSIMILATE')
        self.assertEqual(c.rules.action_token, 'READ_AND_DECOMPILE')
        self.assertTrue(set(c.concrete_primitive_bindings).issubset(set(c.rules.permitted_modules)))

    def test_tier_2_construct_subset_invariant(self):
        self.engine.set_grip(5.5)
        c = self.engine.compile_concept('Windows Named Pipe IPC Server')
        self.assertEqual(c.tier, 'CONSTRUCT')
        self.assertTrue(set(c.concrete_primitive_bindings).issubset(set(c.rules.permitted_modules)))

    def test_tier_3_stress_test_and_active_buffer_eviction(self):
        self.engine.set_grip(9.2)
        c = self.engine.compile_concept('High-Throughput IPC Ring Buffer')
        self.assertEqual(c.tier, 'STRESS_TEST')
        self.assertTrue(set(c.concrete_primitive_bindings).issubset(set(c.rules.permitted_modules)))
        self.assertTrue(c.backpressure_active)
        self.assertGreaterEqual(c.shunt_telemetry['evicted_queue_items'], 1)

    def test_empty_concept_fails_closed(self):
        with self.assertRaises(ContractValidationError):
            self.engine.compile_concept('')

    def test_null_byte_injection_rejected(self):
        with self.assertRaises(ContractValidationError):
            self.engine.compile_concept('bad' + chr(0) + 'concept')

    def test_excessive_length_rejected(self):
        with self.assertRaises(ContractValidationError):
            self.engine.compile_concept('A' * 1025)

    def test_invalid_grip_bounds_rejected(self):
        with self.assertRaises(ContractValidationError):
            self.engine.set_grip(-1.0)
        with self.assertRaises(ContractValidationError):
            self.engine.set_grip(11.0)

    def test_fail_closed_on_corrupt_memory_telemetry(self):
        sub = BoundedExecutionSubstrate()
        orig = sub.get_real_memory_telemetry
        try:
            sub.get_real_memory_telemetry = lambda: {'telemetry_valid': False, 'avail_phys_mb': 0.0}
            active, _ = sub.evaluate_bus_impedance(grip_level=2.0)
            self.assertTrue(active)
        finally:
            sub.get_real_memory_telemetry = orig

if __name__ == '__main__':
    unittest.main()
