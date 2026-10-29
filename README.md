# invariant-engine

A zero-dependency, deterministic, fail-closed bare-metal pipeline and invariant verification engine built strictly on the Python 3.12 standard library. Designed for uncompromising data integrity, rigorous closed-domain validation, and robust stream processing without external package bloat.

## Architecture & Subsystems

The repository is structured into isolated, highly disciplined operational boundaries:

* **`core/`**: System contracts, deterministic NFC Unicode normalization, dictionary key sorting invariance, float zero normalization, and chunked SHA-256 directory tree hashing (`core/hasher.py`, `core/bounds.py`, `core/validator.py`).
* **`runtime/`**: Path traversal sandboxing (`runtime/path_guard.py`), bounded subprocess execution with clean buffer drains (`runtime/process_guard.py`), and a continuous file-stream sentinel featuring mid-write tearing defense and atomic `pulse.txt` heartbeat logging (`runtime/sentinel.py`).
* **`pipeline/`**: Stage 1 tabular/JSON ingress prompt compilation (`pipeline/compiler.py`), Stage 2 post-inference closed-domain auditing (`pipeline/auditor.py`), and an immutable dead-letter quarantine router with non-destructive forensic replay harnesses (`pipeline/quarantine.py`).
* **`tests/`**: Comprehensive unit test vectors verifying hash invariants, fuzzed payloads, and sentinel mortality ceilings (`tests/test_hashes.py`, `tests/test_invariants.py`).
* **Automation Gate**: Native Windows PowerShell CI / pre-commit gateway (`run_invariant_gate.ps1`) executing deterministic unit testing, manifest tree reconciliation, stream ingress audits, and dead-letter replay remediation.

## Quick Start & Verification

Clone the repository and run the certified pre-commit verification gate:

```powershell
git clone [https://github.com/tattooricklong-dev/invariant-engine.git](https://github.com/tattooricklong-dev/invariant-engine.git)
cd invariant-engine
pwsh -ExecutionPolicy Bypass -File .\run_invariant_gate.ps1 -GenerateBaselineIfMissing
