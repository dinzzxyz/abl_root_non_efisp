"""Negative xref/thunk cases using synthetic code, no firmware fixtures."""
import struct
import unittest

from test_bootstate_analysis import SyntheticCode
from map_bootstate import encode_adrl
from trace_ebl_entry import address_references, analyze, resolve_table_thunk


class EblEntryTests(unittest.TestCase):
    def test_interleaved_adrps_and_nonidentity_rvas(self):
        a = encode_adrl(0x8120, 0x1d278, "x0")
        b = encode_adrl(0x8124, 0x1d460, "x1")
        rows = address_references(SyntheticCode(a[:4] + b[:4] + a[4:] + b[4:]))
        self.assertEqual([(r["file_offset"], r["rva"], r["target_rva"])
                          for r in rows], [("0x128", "0x8128", "0x1d278"),
                                          ("0x12c", "0x812c", "0x1d460")])

    def test_clobbers_calls_and_invalid_words_stop_xrefs(self):
        code = encode_adrl(0x8120, 0x19028, "x0")
        for middle in ["00008052", "04000094", "ffffffff"]:
            with self.subTest(middle=middle):
                view = SyntheticCode(code[:4] + bytes.fromhex(middle) + code[4:])
                self.assertEqual(address_references(view), [])

    def test_branch_join_does_not_inherit_only_fallthrough_value(self):
        # Incoming B.EQ skips the ADRP, so the ADD has no guaranteed page value.
        code = encode_adrl(0x8124, 0x19028, "x0")
        view = SyntheticCode(bytes.fromhex("60000054") + code[:4] +
                             bytes.fromhex("1f2003d5") + code[4:])
        self.assertEqual(address_references(view), [])

    def test_table_thunk_uses_rva_mapping_and_rejects_loop(self):
        view = SyntheticCode(bytes.fromhex("01000014c0035fd6"))
        data = bytearray(view.data)
        struct.pack_into("<Q", data, 0x20, 0x8120)
        view.data = bytes(data)
        resolved = resolve_table_thunk(view, view.rva(0x20), 0)
        self.assertEqual(resolved["pointer_rva"], "0x8120")
        self.assertEqual(resolved["target_rva"], "0x8124")
        self.assertEqual(resolved["thunks"][0]["file_offset"], "0x120")
        data[0x120:0x124] = bytes.fromhex("00000014")
        view.data = bytes(data)
        with self.assertRaisesRegex(ValueError, "Loop"):
            resolve_table_thunk(view, view.rva(0x20), 0)

    def test_unknown_images_fail_before_pe_parsing(self):
        with self.assertRaisesRegex(ValueError, "Unknown QcomBds PE hash"):
            analyze(b"different firmware", b"different firmware")


if __name__ == "__main__":
    unittest.main()
