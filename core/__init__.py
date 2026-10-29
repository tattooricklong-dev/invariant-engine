"""
core: System contracts, deterministic hashing, and invariant validation.
"""

from core.bounds import (
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILURE,
    EXIT_SUBPROCESS_FAILURE,
    EXIT_TIMEOUT_INTERRUPT,
    BaremetalEngineError,
    SecurityBoundaryViolation,
    SchemaContractViolation,
    SubprocessExecutionError,
    ProcessTimeoutExpired,
    FieldSpec,
    SymmetricalContract,
)
from core.hasher import CanonicalHasher, DirectoryReconciler, FileManifestRecord
from core.validator import InvariantValidator

__all__ = [
    "EXIT_SUCCESS",
    "EXIT_VALIDATION_FAILURE",
    "EXIT_SUBPROCESS_FAILURE",
    "EXIT_TIMEOUT_INTERRUPT",
    "BaremetalEngineError",
    "SecurityBoundaryViolation",
    "SchemaContractViolation",
    "SubprocessExecutionError",
    "ProcessTimeoutExpired",
    "FieldSpec",
    "SymmetricalContract",
    "CanonicalHasher",
    "DirectoryReconciler",
    "FileManifestRecord",
    "InvariantValidator",
]