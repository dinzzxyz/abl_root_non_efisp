"""Negative cases for structural matching, using synthetic ARM64 instructions."""
import struct
import sys
import unittest
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from map_bootstate import (View, adrl, analyze_image, encode_adrl,
                           find_bootstate_blocks, find_local_sink)


class SyntheticCode(View):
    """Non-identity RVA mapping, without copying firmware into test fixtures."""

    def __init__(self, code, rva=0x8120):
        self.data = bytes(0x120) + code
        self.delta = rva - 0x120
        self.code = [(0x120, len(self.data))]
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    def rva(self, offset):
        return offset + self.delta

    def offset(self, rva):
        return rva - self.delta


# LDR stack value; TST; B.EQ to LDRB; MOV; B to merge; LDRB/CMP/CSET/LSL.
BLOCK = bytes.fromhex("e81b40f91f1d0072600000542800805205000014"
                      "480340391f010071e8079f1a08791f53")


class BootstateStructuralTests(unittest.TestCase):
    def test_branch_targets_and_distinct_address_spaces(self):
        view = SyntheticCode(BLOCK)
        hits = find_bootstate_blocks(view)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["offset"], 0x124)
        self.assertEqual(hits[0]["instructions"][0].address, 0x8124)
        self.assertEqual(hits[0]["stack_slot"], 0x30)

        # An otherwise matching unconditional branch skips past the merge.
        altered = bytearray(BLOCK)
        altered[16:20] = bytes.fromhex("06000014")
        self.assertEqual(find_bootstate_blocks(SyntheticCode(bytes(altered))), [])
        # A condition that goes to CMP rather than LDRB is also rejected.
        altered = bytearray(BLOCK)
        altered[8:12] = bytes.fromhex("80000054")
        self.assertEqual(find_bootstate_blocks(SyntheticCode(bytes(altered))), [])

    def test_sink_rejects_register_clobber_and_intervening_branch(self):
        reload = bytes.fromhex("ea1b40f9")
        store = bytes.fromhex("ea030139")
        for middle, expected in ((b"", 1),
                                 (bytes.fromhex("0a0080d2"), 0),  # MOV X10,#0
                                 (bytes.fromhex("01000014"), 0)):  # B +4
            view = SyntheticCode(BLOCK + reload + middle + store)
            block = find_bootstate_blocks(view)[0]
            self.assertEqual(len(find_local_sink(view, block)), expected)

    def test_adrl_encoding_across_page_boundary(self):
        pc, target = 0x1FFC, 0x8B7F6
        encoded = encode_adrl(pc, target, "x9")
        view = SyntheticCode(encoded, rva=pc)
        self.assertEqual(adrl(view, 0x120), (target, "x9"))
        # Confirm the two instructions really do straddle a 4 KiB boundary.
        ins = view.instructions(0x120, 8)
        self.assertEqual([i.address for i in ins], [0x1FFC, 0x2000])
        self.assertEqual(struct.unpack_from("<I", encoded)[0] & 31, 9)

    def test_unknown_hash_fails_before_pe_parsing(self):
        with self.assertRaisesRegex(ValueError, "Unknown PE hash"):
            analyze_image(b"not a known firmware image")


if __name__ == "__main__":
    unittest.main()
