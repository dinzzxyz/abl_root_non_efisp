import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from analyze_boot_metadata import parse_report, compare_prefixes

TABLE = "GPT_TABLE disk=sde sector_bytes=4096 entry_count=4 entry_size=128\n"
ROW = ("GPT_ENTRY\tdisk=sde\tindex=1\tname=uefivarstore\t"
       "type_guid=165bd6bc-9250-4ac8-95a7-a93f4a440066\t"
       "first_lba=100\tlast_lba=227\tsize_bytes=524288\tesp_type=0\n")


class MetadataAnalysisTests(unittest.TestCase):
    def test_tabs_and_literal_escaped_tabs_produce_same_result(self):
        self.assertEqual(parse_report(TABLE + ROW),
                         parse_report(TABLE + ROW.replace("\t", "\\t")))

    def test_does_not_trust_reported_esp_flag_or_inconsistent_size(self):
        for wrong in (ROW.replace("esp_type=0", "esp_type=1"),
                      ROW.replace("size_bytes=524288", "size_bytes=1024")):
            with self.assertRaises(ValueError):
                parse_report(TABLE + wrong)

    def test_prefix_hash_match_also_requires_exact_reference_length(self):
        report = {"firmware": [{"name": "abl_a", "status": "ok", "prefix_bytes": 32,
                                "bytes_read": 32, "sha256": "a" * 64}]}
        manifest = {"members": [{"name": "cn/abl.elf", "size_bytes": 32,
                                  "sha256": "a" * 64}]}
        self.assertEqual(compare_prefixes(report, manifest)["firmware"][0][
            "matching_reference_files"], ["cn/abl.elf"])
        report["firmware"][0]["bytes_read"] = 31
        self.assertEqual(compare_prefixes(report, manifest)["firmware"][0][
            "matching_reference_files"], [])


if __name__ == "__main__":
    unittest.main()
