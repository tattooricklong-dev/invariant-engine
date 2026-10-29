"""
tests/test_hashes.py: Verification of deterministic hashing across types and manifests.
"""

from pathlib import Path
import tempfile
import shutil
import unittest

from core.hasher import CanonicalHasher, DirectoryReconciler


class TestHashes(unittest.TestCase):

    def test_dictionary_key_sorting_invariance(self):
        obj_a = {"z": 100, "a": "text", "m": [1, 2, 3]}
        obj_b = {"a": "text", "m": [1, 2, 3], "z": 100}
        self.assertEqual(CanonicalHasher.digest(obj_a), CanonicalHasher.digest(obj_b))

    def test_unicode_nfc_normalization(self):
        composed = "caf\u00e9"
        decomposed = "cafe\u0301"
        self.assertEqual(CanonicalHasher.digest(composed), CanonicalHasher.digest(decomposed))

    def test_float_zero_normalization(self):
        obj_positive_zero = {"val": 0.0}
        obj_negative_zero = {"val": -0.0}
        self.assertEqual(
            CanonicalHasher.digest(obj_positive_zero),
            CanonicalHasher.digest(obj_negative_zero),
        )

    def test_directory_manifest_canonical_ordering(self):
        temp_dir = Path(tempfile.mkdtemp(prefix="manifest_test_"))
        try:
            (temp_dir / "z_file.txt").write_bytes(b"content_z")
            (temp_dir / "a_file.txt").write_bytes(b"content_a")
            sub = temp_dir / "sub_dir"
            sub.mkdir()
            (sub / "m_file.txt").write_bytes(b"content_m")

            reconciler_1 = DirectoryReconciler(temp_dir)
            manifest_1 = reconciler_1.generate_manifest()
            root_hash_1 = reconciler_1.compute_root_hash(manifest_1)

            reconciler_2 = DirectoryReconciler(temp_dir)
            manifest_2 = reconciler_2.generate_manifest()
            root_hash_2 = reconciler_2.compute_root_hash(manifest_2)

            self.assertEqual(root_hash_1, root_hash_2)
            self.assertEqual(len(manifest_1), 3)
            self.assertEqual(manifest_1[0].relative_path, "a_file.txt")
            self.assertEqual(manifest_1[1].relative_path, "sub_dir/m_file.txt")
            self.assertEqual(manifest_1[2].relative_path, "z_file.txt")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()