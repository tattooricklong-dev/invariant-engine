#!/usr/bin/env python3
"""
baremetal_cli.py: Automated CLI for Invariant Engine Operations.

Commands:
  reconcile       - Compute canonical directory manifest and reconcile against reference baseline.
  replay-audit    - Non-destructively replay quarantine dead-letters against updated schemas.
  stream-ingress  - Ingest target file stream or stdin through SymmetricalContract into primary/quarantine sinks.
  sentinel        - Run bounded continuous stream sentinel loop.

Standard Library Only: argparse, json, sys, os, pathlib, typing.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence

from core.bounds import (
    EXIT_SUCCESS,
    EXIT_VALIDATION_FAILURE,
    EXIT_SUBPROCESS_FAILURE,
    FieldSpec,
    SymmetricalContract,
)
from core.hasher import CanonicalHasher, DirectoryReconciler, FileManifestRecord
from core.validator import InvariantValidator
from pipeline.compiler import PromptCompiler
from pipeline.quarantine import QuarantineRecord, QuarantineReplayHarness, QuarantineRouter
from runtime.path_guard import PathSanitizer
from runtime.sentinel import BoundedStreamSentinel


def handle_reconcile(args: argparse.Namespace) -> int:
    workspace_root = Path(args.workspace).resolve()
    sanitizer = PathSanitizer(workspace_root)
    sanitizer.validate_safe_path(workspace_root, must_exist=True)

    ignore_patterns = args.ignore.split(",") if args.ignore else [".git", "__pycache__", ".pytest_cache"]
    reconciler = DirectoryReconciler(workspace_root, chunk_size=args.chunk_size)
    manifest = reconciler.generate_manifest(ignore_patterns=ignore_patterns)
    root_hash = reconciler.compute_root_hash(manifest)

    if args.baseline:
        baseline_path = sanitizer.validate_safe_path(args.baseline, must_exist=True)
        with open(baseline_path, "r", encoding="utf-8") as fh:
            baseline_data = json.load(fh)

        diff = reconciler.reconcile_against_target(baseline_data)

        print("======================================================================")
        print("  DIRECTORY MANIFEST RECONCILIATION REPORT")
        print("======================================================================")
        print(f"Workspace Root:       {workspace_root}")
        print(f"Baseline Manifest:    {baseline_path}")
        print(f"Current Tree Digest:  {root_hash}")
        print("----------------------------------------------------------------------")
        print(f"UNMODIFIED: {len(diff['unmodified'])}")
        print(f"MODIFIED:   {len(diff['modified'])}")
        for item in diff["modified"]:
            print(f"  [~] {item}")
        print(f"CREATED:    {len(diff['created'])}")
        for item in diff["created"]:
            print(f"  [+] {item}")
        print(f"DELETED:    {len(diff['deleted'])}")
        for item in diff["deleted"]:
            print(f"  [-] {item}")
        print("======================================================================")

        if diff["modified"] or diff["created"] or diff["deleted"]:
            return EXIT_VALIDATION_FAILURE
        return EXIT_SUCCESS

    output_payload = {
        "workspace_root": str(workspace_root),
        "tree_root_sha256": root_hash,
        "total_files": len(manifest),
        "manifest": [r.to_dict() for r in manifest],
    }

    if args.output:
        out_path = sanitizer.validate_safe_path(args.output, must_exist=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(output_payload, indent=2, sort_keys=True))
        print(f"[RECONCILE] Manifest written to {out_path} (Root SHA-256: {root_hash})")
    else:
        print(json.dumps(output_payload, indent=2, sort_keys=True))

    return EXIT_SUCCESS


def handle_replay_audit(args: argparse.Namespace) -> int:
    quarantine_dir = Path(args.quarantine_dir).resolve()
    router = QuarantineRouter(quarantine_dir)
    replay_harness = QuarantineReplayHarness(router)

    records = replay_harness.load_dead_letter_records()
    if not records:
        print(f"[REPLAY] No quarantined records found in: {router.log_file}")
        return EXIT_SUCCESS

    contract = SymmetricalContract.standard_telemetry_tuple()
    validator = InvariantValidator(contract=contract)

    if args.sources:
        for src in args.sources.split(","):
            clean_src = src.strip()
            if clean_src:
                validator.register_grounded_source(clean_src)

    strip_fields = [f.strip() for f in args.strip_fields.split(",")] if args.strip_fields else []
    transformer_fn = (
        (lambda payload: QuarantineReplayHarness.strip_fields(payload, strip_fields))
        if strip_fields
        else None
    )

    results = replay_harness.batch_replay(
        validation_fn=validator.validate_record,
        transformer_fn=transformer_fn,
    )

    passed = [r for r in results if r.replayed_success]
    failed = [r for r in results if not r.replayed_success]

    print("======================================================================")
    print("  FORENSIC DEAD-LETTER REPLAY AUDIT")
    print("======================================================================")
    print(f"Log Source:         {router.log_file}")
    print(f"Total Evaluated:    {len(results)}")
    print(f"Remediated/Passed:  {len(passed)}")
    print(f"Rejected/Failed:    {len(failed)}")
    if strip_fields:
        print(f"Stripped Fields:    {strip_fields}")
    print("----------------------------------------------------------------------")

    for idx, f in enumerate(failed, start=1):
        print(f"[{idx}] SHA: {f.original_sha256[:16]}... | REASON: {f.failure_reason}")

    print("======================================================================")
    return EXIT_SUCCESS if len(failed) == 0 else EXIT_VALIDATION_FAILURE


def handle_stream_ingress(args: argparse.Namespace) -> int:
    root_jail = Path(args.workspace).resolve() if args.workspace else Path(".").resolve()
    sanitizer = PathSanitizer(root_jail)

    quarantine_dir = sanitizer.validate_safe_path(args.quarantine_dir, must_exist=False)
    router = QuarantineRouter(quarantine_dir)

    contract = SymmetricalContract.standard_telemetry_tuple()
    validator = InvariantValidator(contract=contract)

    if args.sources:
        for s in args.sources.split(","):
            s_clean = s.strip()
            if s_clean:
                validator.register_grounded_source(s_clean)

    compiler = PromptCompiler(contract=contract, validator=validator, quarantine=router)

    target_input = args.input_file or args.input_log
    if target_input:
        input_path = sanitizer.validate_safe_path(target_input, must_exist=True)
        with open(input_path, "r", encoding="utf-8") as fh:
            raw_data = fh.read()
    else:
        if sys.stdin.isatty():
            print("[INGRESS] Awaiting input from stdin (Ctrl+D to terminate)...", file=sys.stderr)
        raw_data = sys.stdin.read()

    valid_records = compiler.compile_ingress_block(raw_data)

    if args.output:
        out_path = sanitizer.validate_safe_path(args.output, must_exist=False)
        with open(out_path, "w", encoding="utf-8") as fh:
            for rec in valid_records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"[INGRESS] Stream processed: {len(valid_records)} accepted -> {out_path}", file=sys.stderr)
        print(f"[INGRESS] Quarantined: {router.quarantined_count} records -> {router.log_file}", file=sys.stderr)
    else:
        for rec in valid_records:
            print(json.dumps(rec, ensure_ascii=False))

    return EXIT_SUCCESS if router.quarantined_count == 0 else EXIT_VALIDATION_FAILURE


def handle_sentinel(args: argparse.Namespace) -> int:
    sources = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else []
    target_input = args.input_file or args.input_log
    if not target_input:
        print("[ERROR] Sentinel requires an input file/log via -i/--input-file or --input-log.", file=sys.stderr)
        return EXIT_VALIDATION_FAILURE

    sentinel = BoundedStreamSentinel(
        workspace_root=args.workspace,
        input_log=target_input,
        accepted_egress=args.output,
        quarantine_dir=args.quarantine_dir,
        grounded_sources=sources,
        max_runtime_seconds=args.max_runtime,
        max_records=args.max_records,
        poll_interval_seconds=args.poll_interval,
    )
    return sentinel.run_bounded_loop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baremetal_cli.py",
        description="Invariant Engine Bare-Metal CLI: Deterministic Audits & Stream Ingress.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_reconcile = subparsers.add_parser("reconcile", help="Generate or reconcile canonical directory manifests.")
    p_reconcile.add_argument("-w", "--workspace", default=".", help="Root workspace directory.")
    p_reconcile.add_argument("-b", "--baseline", default=None, help="Baseline manifest JSON file for diff check.")
    p_reconcile.add_argument("-o", "--output", default=None, help="Output JSON path to save current manifest.")
    p_reconcile.add_argument("--ignore", default=".git,__pycache__,.pytest_cache", help="Comma-separated ignore patterns.")
    p_reconcile.add_argument("--chunk-size", type=int, default=65536, help="File streaming chunk size in bytes.")

    p_replay = subparsers.add_parser("replay-audit", help="Audit and replay quarantined dead-letters.")
    p_replay.add_argument("-q", "--quarantine-dir", default="./quarantine", help="Path to quarantine directory.")
    p_replay.add_argument("-s", "--sources", default=None, help="Comma-separated verified source citation identifiers.")
    p_replay.add_argument("--strip-fields", default=None, help="Comma-separated field names to deterministically strip.")

    p_ingress = subparsers.add_parser("stream-ingress", help="Ingest file or stdin through symmetrical schema compiler.")
    p_ingress.add_argument("-w", "--workspace", default=".", help="Root jail workspace directory.")
    p_ingress.add_argument("-i", "--input-file", default=None, help="Target input file path.")
    p_ingress.add_argument("--input-log", default=None, help="Alias for input file path.")
    p_ingress.add_argument("-o", "--output", default=None, help="Primary egress file for valid JSON lines.")
    p_ingress.add_argument("-q", "--quarantine-dir", default="./quarantine", help="Directory for quarantined logs.")
    p_ingress.add_argument("-s", "--sources", default=None, help="Comma-separated verified source citation identifiers.")

    p_sentinel = subparsers.add_parser("sentinel", help="Run bounded continuous stream sentinel.")
    p_sentinel.add_argument("-w", "--workspace", default=".", help="Root jail workspace directory.")
    p_sentinel.add_argument("-i", "--input-file", default=None, help="Target input log file path.")
    p_sentinel.add_argument("--input-log", default=None, help="Alias for input log file path.")
    p_sentinel.add_argument("-o", "--output", default="accepted.jsonl", help="Primary egress file for valid JSON lines.")
    p_sentinel.add_argument("-q", "--quarantine-dir", default="./quarantine", help="Directory for quarantined logs.")
    p_sentinel.add_argument("-s", "--sources", default="", help="Comma-separated verified source citation identifiers.")
    p_sentinel.add_argument("--max-runtime", type=float, default=60.0, help="Hard runtime ceiling in seconds.")
    p_sentinel.add_argument("--max-records", type=int, default=1000, help="Hard record count ceiling.")
    p_sentinel.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval in seconds.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "reconcile":
        code = handle_reconcile(args)
    elif args.command == "replay-audit":
        code = handle_replay_audit(args)
    elif args.command == "stream-ingress":
        code = handle_stream_ingress(args)
    elif args.command == "sentinel":
        code = handle_sentinel(args)
    else:
        code = EXIT_VALIDATION_FAILURE

    sys.exit(code)


if __name__ == "__main__":
    main()