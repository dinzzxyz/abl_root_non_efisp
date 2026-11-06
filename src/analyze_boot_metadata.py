#!/usr/bin/env python3
"""Compare reported boot-image prefixes and GPT metadata with the input manifest."""
import argparse
import hashlib
import json
import re
from pathlib import Path

ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


def fields(line):
    # Some Android awk versions/report transfers preserve the separator literally.
    return dict(re.findall(r"(\w+)=([^\s]+)", line.replace("\\t", "\t")))


def parse_report(text):
    report = {"properties": {}, "firmware": [], "tables": [],
              "entries": [], "partition_sizes": {}, "kernel_config_lines": []}
    for line in text.splitlines():
        if re.match(r"^ro\.[^=]+=", line):
            key, value = line.split("=", 1)
            report["properties"][key] = value
        elif line.startswith("uid="):
            report["reported_uid"] = int(line.split("=", 1)[1])
        elif line.startswith("FIRMWARE "):
            item = fields(line)
            if item.get("status") == "ok":
                for key in ("prefix_bytes", "bytes_read"):
                    item[key] = int(item[key])
                if not re.fullmatch("[0-9a-f]{64}", item.get("sha256", "")):
                    raise ValueError("Invalid reported firmware digest")
            report["firmware"].append(item)
        elif line.startswith("GPT_TABLE "):
            item = fields(line)
            for key in ("sector_bytes", "entry_count", "entry_size"):
                item[key] = int(item[key])
            report["tables"].append(item)
        elif line.startswith("GPT_ENTRY"):
            item = fields(line)
            for key in ("index", "first_lba", "last_lba", "size_bytes", "esp_type"):
                item[key] = int(item[key])
            item["is_esp_type_computed"] = item["type_guid"].lower() == ESP_TYPE
            if bool(item["esp_type"]) != item["is_esp_type_computed"]:
                raise ValueError("Reported ESP flag differs from type GUID")
            report["entries"].append(item)
        elif line.startswith("PARTITION "):
            item = fields(line)
            report["partition_sizes"][item["name"]] = int(item["size_bytes"])
        elif line.startswith(("CONFIG_EFI", "# CONFIG_EFI")):
            report["kernel_config_lines"].append(line)
        elif line == "GPT_CRC_CHECK=not_performed":
            report["gpt_crc_verified"] = False
        elif line == "EFI_RUNTIME_DIRECTORY=unavailable":
            report["efi_runtime_directory_available"] = False
    tables = {x["disk"]: x for x in report["tables"]}
    seen = set()
    for item in report["entries"]:
        table = tables[item["disk"]]
        identity = (item["disk"], item["index"])
        if identity in seen or not 1 <= item["index"] <= table["entry_count"]:
            raise ValueError("Duplicate or out-of-range GPT entry")
        seen.add(identity)
        calculated = (item["last_lba"] - item["first_lba"] + 1) * table["sector_bytes"]
        if item["last_lba"] < item["first_lba"] or item["size_bytes"] != calculated:
            raise ValueError("Reported GPT size inconsistent with LBAs")
        reported = report["partition_sizes"].get(item["name"])
        if reported is not None and reported != calculated:
            raise ValueError("Block-device size differs from GPT entry")
    for disk in tables:
        rows = sorted((x for x in report["entries"] if x["disk"] == disk),
                      key=lambda x: x["first_lba"])
        if any(a["last_lba"] >= b["first_lba"] for a, b in zip(rows, rows[1:])):
            raise ValueError("Reported GPT partitions overlap")
    return report


def compare_prefixes(report, manifest):
    references = {x["name"]: x for x in manifest["members"]}
    for item in report["firmware"]:
        item["matching_reference_files"] = []
        if item.get("status") != "ok":
            continue
        kind = item["name"].rsplit("_", 1)[0]
        for prefix in ("cn", "eng rom"):
            name = f"{prefix}/{kind}.elf"
            known = references.get(name)
            if known and item["bytes_read"] == item["prefix_bytes"] == known["size_bytes"]:
                if item["sha256"] == known["sha256"]:
                    item["matching_reference_files"].append(name)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "INPUTS.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--boot-properties-spoofed", action="store_true")
    args = parser.parse_args()
    data = args.report.read_bytes()
    result = compare_prefixes(parse_report(data.decode("utf-8-sig")),
                              json.loads(args.manifest.read_text()))
    result["source_name"] = args.report.name
    result["source_sha256"] = hashlib.sha256(data).hexdigest()
    result["boot_properties_spoofed_user_confirmed"] = True if args.boot_properties_spoofed else None
    result["prefix_scope"] = "Complete supplied image-file prefixes only; remaining bytes of each partition were not hashed"
    result["esp_type_matches"] = [x["name"] for x in result["entries"] if x["is_esp_type_computed"]]
    result["upstream_internal_esp_store_candidates"] = [
        x["name"] for x in result["entries"]
        if x["name"] == "efisp" or x["is_esp_type_computed"]]
    result["not_proven"] = [
        "real bootloader lock state", "custom BDS execution",
        "modified firmware authentication acceptance", "UEFI variable writes",
        "kernel EFI runtime handoff", "complete partition trailing-byte contents"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "reported_uid": result.get("reported_uid"),
        "firmware_reference_matches": {
            x["name"]: x["matching_reference_files"] for x in result["firmware"]},
        "reported_gpt_disks": len(result["tables"]),
        "reported_partition_entries": len(result["entries"]),
        "esp_type_matches": result["esp_type_matches"],
        "kernel_config_lines": result["kernel_config_lines"],
    }, indent=2))


if __name__ == "__main__":
    main()
