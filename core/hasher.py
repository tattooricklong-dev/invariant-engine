"""
core/hasher.py: Canonical serialization, SHA-256 hashing, and directory tree reconciliation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import unicodedata


@dataclass(frozen=True)
class FileManifestRecord:
    """Immutable manifest entry for a single file within a canonical tree."""
    relative_path: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


class CanonicalHasher:
    """Serializes data structures with sorted dictionary keys and NFC Unicode."""

    @staticmethod
    def normalize_text(text: str, form: str = "NFC") -> str:
        return unicodedata.normalize(form, text)

    @classmethod
    def canonical_json_bytes(cls, obj: Any) -> bytes:
        def _sanitize(val: Any) -> Any:
            if isinstance(val, str):
                return cls.normalize_text(val)
            if isinstance(val, (bytes, bytearray)):
                return val.decode("utf-8", errors="replace")
            if isinstance(val, dict):
                return {
                    cls.normalize_text(str(k)): _sanitize(v)
                    for k, v in sorted(val.items(), key=lambda item: cls.normalize_text(str(item[0])))
                }
            if isinstance(val, (list, tuple)):
                return [_sanitize(v) for v in val]
            if isinstance(val, set):
                return sorted([_sanitize(v) for v in val], key=lambda x: str(x))
            if isinstance(val, float):
                if val == 0.0:
                    val = 0.0
                return round(val, 8)
            return val

        sanitized = _sanitize(obj)
        return json.dumps(
            sanitized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def digest(cls, data: Union[str, bytes, Dict[str, Any], List[Any]], algorithm: str = "sha256") -> str:
        hasher = hashlib.new(algorithm)
        if isinstance(data, (dict, list, set, tuple)):
            payload_bytes = cls.canonical_json_bytes(data)
        elif isinstance(data, str):
            payload_bytes = cls.normalize_text(data).encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            payload_bytes = bytes(data)
        else:
            payload_bytes = cls.canonical_json_bytes(data)

        hasher.update(payload_bytes)
        return hasher.hexdigest()

    @classmethod
    def file_digest(cls, file_path: Union[str, Path], chunk_size: int = 65536) -> str:
        path = Path(file_path).resolve()
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            while chunk := fh.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()


class DirectoryReconciler:
    """Deterministic workspace snapshot engine and tree diff reconciler."""

    def __init__(self, root_dir: Union[str, Path], chunk_size: int = 65536):
        self.root = Path(root_dir).resolve()
        self.chunk_size = chunk_size
        if not self.root.exists() or not self.root.is_dir():
            raise FileNotFoundError(f"Target directory does not exist or is not a directory: {self.root}")

    def compute_file_record(self, file_path: Path) -> FileManifestRecord:
        resolved = file_path.resolve()
        hasher = hashlib.sha256()
        total_bytes = 0

        with open(resolved, "rb") as fh:
            while chunk := fh.read(self.chunk_size):
                hasher.update(chunk)
                total_bytes += len(chunk)

        rel_posix = file_path.relative_to(self.root).as_posix()
        norm_path = CanonicalHasher.normalize_text(rel_posix)

        return FileManifestRecord(
            relative_path=norm_path,
            sha256=hasher.hexdigest(),
            size_bytes=total_bytes,
        )

    def generate_manifest(self, ignore_patterns: Optional[Sequence[str]] = None) -> List[FileManifestRecord]:
        ignore_set = set(ignore_patterns or [".git", "__pycache__", ".pytest_cache"])
        records: List[FileManifestRecord] = []
        all_paths: List[Path] = []

        for current_root, dirs, files in os.walk(self.root, followlinks=False):
            dirs.sort()
            files.sort()
            dirs[:] = [d for d in dirs if d not in ignore_set]

            cur_path = Path(current_root)
            for f in files:
                if f in ignore_set:
                    continue
                file_path = cur_path / f
                if file_path.is_file() and not file_path.is_symlink():
                    all_paths.append(file_path)

        all_paths.sort(key=lambda p: CanonicalHasher.normalize_text(p.relative_to(self.root).as_posix()))
        for p in all_paths:
            records.append(self.compute_file_record(p))

        return records

    def compute_root_hash(self, manifest: Sequence[FileManifestRecord]) -> str:
        raw_manifest_data = [rec.to_dict() for rec in manifest]
        return CanonicalHasher.digest(raw_manifest_data)

    def reconcile_against_target(
        self,
        reference_manifest: Union[Sequence[FileManifestRecord], Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        if isinstance(reference_manifest, dict):
            raw_files = reference_manifest.get("manifest", [])
            ref_records = [
                FileManifestRecord(
                    relative_path=item["relative_path"],
                    sha256=item["sha256"],
                    size_bytes=item["size_bytes"],
                )
                for item in raw_files
            ]
        else:
            ref_records = list(reference_manifest)

        current_manifest = self.generate_manifest()
        curr_map = {r.relative_path: r.sha256 for r in current_manifest}
        ref_map = {r.relative_path: r.sha256 for r in ref_records}

        curr_keys = set(curr_map.keys())
        ref_keys = set(ref_map.keys())

        created = sorted(list(curr_keys - ref_keys))
        deleted = sorted(list(ref_keys - curr_keys))
        common = curr_keys & ref_keys

        modified = []
        unmodified = []
        for k in sorted(list(common)):
            if curr_map[k] == ref_map[k]:
                unmodified.append(k)
            else:
                modified.append(k)

        return {
            "unmodified": unmodified,
            "modified": modified,
            "created": created,
            "deleted": deleted,
        }