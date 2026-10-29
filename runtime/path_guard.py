"""
runtime/path_guard.py: Path traversal prevention & directory sandboxing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Union
from core.bounds import SecurityBoundaryViolation


class PathSanitizer:
    """Restricts file operations strictly to a declared root boundary."""

    RESERVED_NAMES = frozenset({
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    })

    def __init__(self, root_workspace: Union[str, Path]):
        self.root = Path(root_workspace).resolve()
        if not self.root.exists():
            self.root.mkdir(parents=True, exist_ok=True)

    def validate_safe_path(self, target: Union[str, Path], must_exist: bool = False) -> Path:
        target_str = str(target)
        if "\0" in target_str:
            raise SecurityBoundaryViolation(f"Null-byte injection detected in target path: {target_str!r}")

        raw_path = Path(target)
        for part in raw_path.parts:
            stem_upper = Path(part).stem.upper()
            if stem_upper in self.RESERVED_NAMES:
                raise SecurityBoundaryViolation(f"Reserved OS device name detected in path: '{part}'")

        if not raw_path.is_absolute():
            resolved = (self.root / raw_path).resolve()
        else:
            resolved = raw_path.resolve()

        if resolved != self.root and self.root not in resolved.parents:
            raise SecurityBoundaryViolation(
                f"SECURITY BREACH: Path traversal attempted. Target '{target}' resolves to "
                f"'{resolved}', which is outside root perimeter '{self.root}'."
            )

        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Target path does not exist on disk: {resolved}")

        return resolved

    def safe_open_read(self, target: Union[str, Path], mode: str = "r", encoding: str = "utf-8") -> Any:
        safe_path = self.validate_safe_path(target, must_exist=True)
        return open(safe_path, mode=mode, encoding=encoding if "b" not in mode else None)

    def safe_open_write(self, target: Union[str, Path], mode: str = "w", encoding: str = "utf-8") -> Any:
        safe_path = self.validate_safe_path(target, must_exist=False)
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        return open(safe_path, mode=mode, encoding=encoding if "b" not in mode else None)