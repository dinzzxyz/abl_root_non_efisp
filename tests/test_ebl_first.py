"""CPU/ABI and bounded parser checks without shipping the private logo input."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from map_bootstate import immediate, encode_adrl
from test_bootstate_analysis import SyntheticCode
from plan_ebl_first import (ABL_GUID_RVA, STUB_RVA, build_stub, emulate,
                            encode_adr, encode_bl, plan_for_pe)
from analyze_logo_donor import audit_qcom_v7, read_override, scan_partitions, tlv


class EblFirstTests(unittest.TestCase):
    def test_branch_and_adr_use_pc_rva_with_both_directions(self):
        for target in [0x1000, 0x1C900]:
            view = SyntheticCode(encode_bl(0x8120, target))
            self.assertEqual(immediate(view.instructions(0x120, 4)[0], 0), target)
            view = SyntheticCode(encode_adr(0x8120, target, 1))
            self.assertEqual(immediate(view.instructions(0x120, 4)[0], 1), target)

    def test_encoders_reject_unaligned_and_out_of_range_targets(self):
        for pc, target in [(0, 3), (0, 1 << 27), (1 << 28, 0)]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                encode_bl(pc, target)
        with self.assertRaises(ValueError):
            encode_adr(0, 1 << 20, 1)

    def test_real_arm64_bytes_preserve_flow_abi_and_error_fallback(self):
        results = emulate()
        self.assertEqual(len(results["cases"]), 8)
        self.assertTrue(results["bds_helper_mocked"])
        self.assertFalse(results["uefi_firmware_executed"])
        self.assertTrue(all(x["original_continuation_reached"] for x in results["cases"]))

    def test_wrong_namespace_or_missing_register_save_is_detected(self):
        wrong_fv = bytearray(build_stub())
        wrong_fv[20:24] = encode_adrl(STUB_RVA + 16, ABL_GUID_RVA, "x0")[4:]
        with self.assertRaisesRegex(ValueError, "namespace"):
            emulate(bytes(wrong_fv))
        missing_save = bytearray(build_stub())
        missing_save[4:8] = bytes.fromhex("1f2003d5")  # NOP instead of STP X19,X20
        with self.assertRaisesRegex(ValueError, "register"):
            emulate(bytes(missing_save))

    def test_unknown_pe_refused_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "Unknown QcomBds"):
            plan_for_pe(b"different build")


class LogoComparisonTests(unittest.TestCase):
    def test_context_hash_block_is_parsed_and_bad_lengths_rejected(self):
        body = (bytes.fromhex("060760867693160204032100") + bytes([1]) * 32 +
                bytes.fromhex("060760867693160201032100") + bytes([2]) * 32)
        block = b"\xA0" + bytes([len(body)]) + body
        self.assertEqual(read_override(block), {"header_sha256": "01" * 32,
                                                "image_sha256": "02" * 32})
        for bad in [block[:-1], b"\x30" + block[1:], b"\x30\x80", b"\x30\x82\x01"]:
            with self.subTest(bad=bad[:2]), self.assertRaises(ValueError):
                read_override(bad)

    def test_unaligned_header_observed_but_truncated_payload_refused(self):
        header = bytearray(512)
        header[:4] = bytes.fromhex("88168858")
        struct.pack_into("<I", header, 4, 3)
        header[8:13] = b"logo1"
        header[48:52] = bytes.fromhex("89168958")
        struct.pack_into("<I", header, 52, 512)
        struct.pack_into("<I", header, 68, 16)
        rows = scan_partitions(b"123" + bytes(header) + b"abc")
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["header_aligned"])
        with self.assertRaisesRegex(ValueError, "truncated"):
            scan_partitions(bytes(header) + b"ab")

    def test_qcom_v7_stock_signature_and_truncated_elf(self):
        root = Path(__file__).resolve().parents[1]
        stock = (root / "annibale/src/OS3.0.307.0.WPKCNXM_abl.elf").read_bytes()
        report, certs, chain, signature = audit_qcom_v7(stock)
        self.assertTrue(report["original_signature_valid_with_embedded_leaf_key"])
        self.assertFalse(report["one_hash_byte_counterfactual_signature_valid"])
        self.assertEqual([len(x) for x in certs], [600, 689, 724])
        self.assertEqual((len(chain), len(signature)), (3360, 104))
        with self.assertRaisesRegex(ValueError, "Truncated ELF"):
            audit_qcom_v7(stock[:7])


if __name__ == "__main__":
    unittest.main()
