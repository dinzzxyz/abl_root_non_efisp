"""Exercise the collector's real embedded AWK parser with synthetic GPT data."""
import shutil
import struct
import subprocess
import unittest
import uuid
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools/collect_boot_metadata.sh"
ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
LINUX = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def record(kind, name, first, last, size=128):
    data = bytearray(size)
    data[:16] = uuid.UUID(kind).bytes_le
    data[16:32] = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef").bytes_le
    struct.pack_into("<QQ", data, 32, first, last)
    encoded = name.encode("utf-16le")
    data[56:56 + len(encoded)] = encoded
    return data


@unittest.skipUnless(shutil.which("awk"), "awk required")
class GptCollectorTests(unittest.TestCase):
    def parse(self, data, *, size=128, count=2, sector=4096):
        source = SCRIPT.read_text()
        program = source.split("# SM8750_GPT_AWK_BEGIN\n", 1)[1].split(
            "# SM8750_GPT_AWK_END", 1)[0]
        numbers = "\n".join(" ".join(str(x) for x in data[i:i + 16])
                            for i in range(0, len(data), 16)) + "\n"
        return subprocess.run(
            ["awk", "-v", f"step={size}", "-v", f"limit={count}",
             "-v", "disk=synthetic", "-v", f"sector={sector}", program],
            input=numbers, text=True, capture_output=True, check=True).stdout

    def test_type_endianness_sector_sizes_and_unique_guid_omission(self):
        data = record(ESP, "EFI_DATA", 2048, 4095) + record(LINUX, "persist", 4096, 8191)
        output = self.parse(data)
        lines = output.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("type_guid=" + ESP, lines[0])
        self.assertIn("size_bytes=8388608", lines[0])
        self.assertIn("esp_type=1", lines[0])
        self.assertIn("name=persist", lines[1])
        self.assertIn("size_bytes=16777216", lines[1])
        self.assertIn("esp_type=0", lines[1])
        self.assertNotIn("deadbeef", output)
        self.assertIn("size_bytes=1048576", self.parse(data, sector=512).splitlines()[0])

    def test_empty_entries_extended_records_and_count_bound(self):
        data = bytes(256) + record(ESP, "EFI_DATA", 10, 19, size=256)
        data += record(ESP, "OUTSIDE_LIMIT", 20, 29, size=256)
        output = self.parse(data, size=256, count=2)
        self.assertEqual(len(output.splitlines()), 1)
        self.assertIn("index=2", output)
        self.assertIn("name=EFI_DATA", output)
        self.assertNotIn("OUTSIDE_LIMIT", output)


if __name__ == "__main__":
    unittest.main()
