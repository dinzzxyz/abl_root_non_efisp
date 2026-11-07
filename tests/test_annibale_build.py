"""Regress the shipped ELF pair and independently verify the signature boundary."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "annibale/src"))
import patch as annibale_patch
from verify_signature import audit, der_object


class AnnibaleBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock = (ROOT / "annibale/src" / annibale_patch.NAME).read_bytes()
        cls.candidate = (ROOT / "annibale" / annibale_patch.NAME).read_bytes()

    def test_rebuild_matches_shipped_elf_report_and_previous_pe_candidate(self):
        rebuilt, report = annibale_patch.rebuild(self.stock)
        self.assertEqual(rebuilt, self.candidate)
        self.assertEqual(report, json.loads((ROOT / "annibale/build-report.json").read_text()))
        before, _ = annibale_patch.unpack_payload(self.stock)
        after, _ = annibale_patch.unpack_payload(rebuilt)
        self.assertEqual(sum(a != b for a, b in zip(before, after)), 10)
        self.assertEqual(rebuilt[:0x1000], self.stock[:0x1000])
        self.assertEqual(rebuilt[0x511B0:], self.stock[0x511B0:])

    def test_one_byte_stock_mutation_rejected_before_rebuild(self):
        changed = bytearray(self.stock)
        changed[0x2000] ^= 1
        with self.assertRaisesRegex(ValueError, "Unknown stock ELF SHA-256"):
            annibale_patch.rebuild(bytes(changed))

    def test_cli_cannot_overwrite_original_with_output(self):
        source = ROOT / "annibale/src" / annibale_patch.NAME
        process = subprocess.run([sys.executable, str(ROOT / "annibale/src/patch.py"),
                                  "--input", str(source), "--output", str(source)],
                                 capture_output=True, text=True, timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("must be different files", process.stderr)
        self.assertEqual(source.read_bytes(), self.stock)

    def test_corrupted_ffs_checksum_or_extent_rejected(self):
        for at in [annibale_patch.OUTER_FFS + 16, annibale_patch.OUTER_FFS + 22]:
            changed = bytearray(self.candidate)
            changed[at] ^= 0x80
            with self.subTest(at=at), self.assertRaises(ValueError):
                annibale_patch.unpack_payload(bytes(changed))

    def test_der_truncation_and_indefinite_length_rejected(self):
        for data in [b"\x30\x80", b"\x30\x82\x01", b"\x30\x04\x02\x01"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                der_object(data)

    def test_original_signature_valid_modified_invalid_despite_valid_digests(self):
        result = audit(self.stock, self.candidate)
        self.assertTrue(result["stock"]["oem_image_signature_valid_with_embedded_leaf_key"])
        self.assertFalse(result["candidate"]["oem_image_signature_valid_with_embedded_leaf_key"])
        self.assertTrue(result["candidate"]["elf_header_and_payload_hashes_valid"])
        self.assertTrue(all(x["cryptographic_signature_valid"]
                            for x in result["candidate"]["certificate_signature_links"]))


if __name__ == "__main__":
    unittest.main()
