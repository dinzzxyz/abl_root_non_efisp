"""Corrupt FAT structures and privacy boundaries, without device fixtures."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyze_live_boot import Fat12, selected_log_lines


def fat12_image():
    # 4096-byte sectors exercise the actual logfs geometry rather than assuming
    # a PC's 512-byte sector. One file spans two noncontiguous data clusters.
    bps, sectors = 4096, 12
    data = bytearray(bps * sectors)
    struct.pack_into("<H", data, 11, bps)
    data[13] = 1
    struct.pack_into("<H", data, 14, 1)
    data[16] = 2
    struct.pack_into("<H", data, 17, 16)
    struct.pack_into("<H", data, 19, sectors)
    struct.pack_into("<H", data, 22, 1)
    data[510:512] = b"\x55\xaa"
    fat = bytearray(bps)

    def link(cluster, value):
        offset = cluster + cluster // 2
        word = struct.unpack_from("<H", fat, offset)[0]
        word = (word & 0xF) | (value << 4) if cluster & 1 else (word & 0xF000) | value
        struct.pack_into("<H", fat, offset, word)

    link(0, 0xFF8)
    link(1, 0xFFF)
    link(2, 4)
    link(4, 0xFFF)
    data[bps:2 * bps] = data[2 * bps:3 * bps] = fat
    root = 3 * bps
    data[root:root + 11] = b"UEFILOG0TXT"
    data[root + 11] = 0x20
    struct.pack_into("<H", data, root + 26, 2)
    struct.pack_into("<I", data, root + 28, bps + 7)
    data[4 * bps:5 * bps] = b"a" * bps
    data[6 * bps:6 * bps + 7] = b"last-7!"
    return data


class LiveBootTests(unittest.TestCase):
    def test_noncontiguous_chain_and_large_sectors(self):
        volume = Fat12(bytes(fat12_image()))
        self.assertEqual(volume.metadata["bytes_per_sector"], 4096)
        self.assertEqual(volume.files()["UEFILOG0.TXT"], b"a" * 4096 + b"last-7!")

    def test_inconsistent_fats_and_truncated_volume_rejected(self):
        bad = fat12_image()
        bad[2 * 4096 + 3] ^= 1
        with self.assertRaisesRegex(ValueError, "FAT copies differ"):
            Fat12(bytes(bad))
        with self.assertRaisesRegex(ValueError, "Truncated FAT volume"):
            Fat12(bytes(fat12_image()[:-4096]))

    def test_cycle_is_rejected(self):
        bad = fat12_image()
        # Cluster 2 -> 2, updating both FAT copies so the chain check is tested.
        for base in [4096, 8192]:
            bad[base + 3] = 2
            bad[base + 4] &= 0xF0
        with self.assertRaisesRegex(ValueError, "cyclic"):
            Fat12(bytes(bad)).files()

    def test_log_allowlist_rejects_sensitive_suffix_and_unrelated_lines(self):
        lines = ("[00003838] INFO: UEFI NV tables are enabled as VOLATILE!\n"
                 "[00004294] VB2: Authenticate complete! boot state is: orange\n"
                 "[00004294] VB2: Authenticate complete! boot state is: orange serial=PRIVATE\n"
                 "Chip ECID: PRIVATE\nandroidboot.panel_cell_id=PRIVATE\n"
                 "arbitrary log message\n")
        result = selected_log_lines(lines.encode() + bytes(50))
        self.assertEqual(len(result["selected_lines"]), 2)
        self.assertNotIn("PRIVATE", str(result))


if __name__ == "__main__":
    unittest.main()
