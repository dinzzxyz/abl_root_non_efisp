"""Verify the actual Ebl-first container, not only its proposed instruction bytes."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "annibale/src"))
sys.path.insert(0, str(ROOT / "src"))
import patch_uefi_ebl_first as uefi
from plan_ebl_first import build_stub, emulate, encode_bl, CALL_RVA, STUB_RVA
from verify_signature import audit


class UefiEblContainerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stock = (ROOT / "annibale/src" / uefi.STOCK_NAME).read_bytes()
        cls.candidate = (ROOT / "annibale" / uefi.NAME).read_bytes()

    def test_exact_elf_rebuild_and_report_preserve_all_other_regions(self):
        result, report = uefi.rebuild(self.stock)
        self.assertEqual(result, self.candidate)
        self.assertEqual(report, json.loads((ROOT / "annibale/uefi-ebl-first-build-report.json").read_text()))
        self.assertEqual(len(result), len(self.stock))
        self.assertEqual(result[:uefi.MAIN_FFS], self.stock[:uefi.MAIN_FFS])
        self.assertEqual(result[uefi.NEXT_FFS:uefi.PAYLOAD_DIGEST],
                         self.stock[uefi.NEXT_FFS:uefi.PAYLOAD_DIGEST])
        self.assertEqual(result[uefi.PAYLOAD_DIGEST + 48:], self.stock[uefi.PAYLOAD_DIGEST + 48:])

    def test_shipped_pe_contains_the_generated_emulated_program_and_call(self):
        expanded, _, files = uefi.unpack_payload(self.candidate)
        pe = expanded[uefi.PE_START:uefi.PE_START + uefi.PE_SIZE]
        stub = pe[STUB_RVA:STUB_RVA + 72]
        self.assertEqual(stub, build_stub())
        self.assertEqual(pe[CALL_RVA:CALL_RVA + 4], encode_bl(CALL_RVA, STUB_RVA))
        self.assertEqual(len(emulate(stub)["cases"]), 8)
        self.assertEqual(len(files), 6)

    def test_source_mutation_and_corrupted_payload_digest_are_rejected(self):
        changed = bytearray(self.stock)
        changed[0x1100] ^= 1
        with self.assertRaisesRegex(ValueError, "Unknown stock UEFI SHA-256"):
            uefi.rebuild(bytes(changed))
        changed = bytearray(self.candidate)
        changed[uefi.STREAM + 40] ^= 1
        with self.assertRaisesRegex(ValueError, "payload SHA-384"):
            uefi.check_elf(bytes(changed))

    def test_pad_header_corruption_and_erased_hole_cannot_hide_next_file(self):
        for replacement in [b"\xFF" * 24, b"\xFE" + self.candidate[0xEFD11:0xEFD28]]:
            changed = bytearray(self.candidate)
            changed[0xEFD10:0xEFD28] = replacement
            with self.subTest(replacement=replacement[:1]), self.assertRaises(ValueError):
                uefi.walk_ffs(bytes(changed), uefi.PAYLOAD_START,
                              uefi.PAYLOAD_END - uefi.PAYLOAD_START)

    def test_candidate_signature_is_invalid_with_exact_original_certificates(self):
        report = audit(self.stock, self.candidate, layout=uefi)
        self.assertTrue(report["stock"]["oem_image_signature_valid_with_embedded_leaf_key"])
        self.assertFalse(report["candidate"]["oem_image_signature_valid_with_embedded_leaf_key"])
        self.assertEqual(report["stock"]["certificate_sha256"], report["candidate"]["certificate_sha256"])
        self.assertEqual(self.stock[uefi.SIGNATURE_START:], self.candidate[uefi.SIGNATURE_START:])
        self.assertEqual(report["stock"]["signature_der_size"], 102)

    def test_cli_refuses_to_overwrite_its_default_input(self):
        path = ROOT / "annibale/src" / uefi.STOCK_NAME
        result = subprocess.run([sys.executable, str(ROOT / "annibale/src/patch_uefi_ebl_first.py"),
                                 "--input", str(path), "--output", str(path)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be different files", result.stderr)
        self.assertEqual(path.read_bytes(), self.stock)


if __name__ == "__main__":
    unittest.main()
