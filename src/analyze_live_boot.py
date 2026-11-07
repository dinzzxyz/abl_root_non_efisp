#!/usr/bin/env python3
"""Analyze private read-only captures; publish metadata and allowlisted log lines.

No device I/O, filesystem mounts, firmware output, or arbitrary log export.
The FAT reader handles bounded FAT12 and short aliases, not general VFAT.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import uuid
import zipfile
from pathlib import Path

from fwlib import (expanded_blobs, named_firmware_files, pe_images,
                   read_member, sha256, write_json)
from map_bootstate import View

MAX_VOLUME = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Fat12:
    """Read a complete, bounded FAT12 volume with matching FAT copies."""

    def __init__(self, data):
        require(512 <= len(data) <= MAX_VOLUME, "FAT input size out of bounds")
        require(data[510:512] == b"\x55\xaa", "FAT boot signature missing")
        self.data = data
        u16 = lambda p: struct.unpack_from("<H", data, p)[0]
        self.bps = u16(11)
        self.spc = data[13]
        reserved, count, root_entries, fat_sectors = u16(14), data[16], u16(17), u16(22)
        total = u16(19) or struct.unpack_from("<I", data, 32)[0]
        require(self.bps in (512, 1024, 2048, 4096), "Unsupported FAT sector size")
        require(self.spc and self.spc <= 128 and self.spc & (self.spc - 1) == 0,
                "Invalid sectors per cluster")
        require(reserved > 0 and count in (1, 2) and 0 < root_entries <= 4096 and fat_sectors > 0,
                "Invalid FAT12 BPB")
        root_sectors = (root_entries * 32 + self.bps - 1) // self.bps
        first_data = reserved + count * fat_sectors + root_sectors
        require(first_data < total and total * self.bps <= len(data), "Truncated FAT volume")
        self.clusters = (total - first_data) // self.spc
        require(0 < self.clusters < 4085, "Volume is not FAT12 by cluster count")
        self.cluster_bytes = self.bps * self.spc
        self.data_offset = first_data * self.bps
        self.root_offset = (reserved + count * fat_sectors) * self.bps
        self.root_bytes = root_entries * 32
        fat_offset, fat_bytes = reserved * self.bps, fat_sectors * self.bps
        self.fat = data[fat_offset:fat_offset + fat_bytes]
        require((self.clusters + 2) * 3 <= len(self.fat) * 2, "FAT table too short")
        for i in range(1, count):
            require(data[fat_offset + i * fat_bytes:fat_offset + (i + 1) * fat_bytes] == self.fat,
                    "FAT copies differ; snapshot is inconsistent")
        self.metadata = {
            "fat_type": "FAT12", "bytes_per_sector": self.bps,
            "sectors_per_cluster": self.spc, "reserved_sectors": reserved,
            "fat_count": count, "fat_copies_equal": True, "sectors_per_fat": fat_sectors,
            "root_entries": root_entries, "total_sectors": total,
            "volume_bytes": total * self.bps, "data_clusters": self.clusters,
            "root_directory_offset": hex(self.root_offset), "data_offset": hex(self.data_offset),
            "reader_scope": "short aliases; LFN records skipped; no writes",
        }

    def chain(self, cluster):
        result, seen = bytearray(), set()
        while cluster < 0xFF8:
            require(2 <= cluster < self.clusters + 2 and cluster not in seen,
                    "Invalid or cyclic FAT cluster chain")
            seen.add(cluster)
            start = self.data_offset + (cluster - 2) * self.cluster_bytes
            require(start + self.cluster_bytes <= len(self.data), "Cluster outside capture")
            result.extend(self.data[start:start + self.cluster_bytes])
            offset = cluster + cluster // 2
            value = struct.unpack_from("<H", self.fat, offset)[0]
            cluster = value >> 4 if cluster & 1 else value & 0xFFF
        return bytes(result)

    def files(self):
        """Return path -> bytes; reject duplicate names, traversal and cycles."""
        result, visited = {}, set()

        def walk(directory, prefix="", depth=0):
            require(depth <= 8, "FAT directory nesting too deep")
            for offset in range(0, len(directory) - 31, 32):
                entry = directory[offset:offset + 32]
                if entry[0] == 0:
                    break
                if entry[0] == 0xE5 or entry[11] == 0x0F or entry[11] & 0x08:
                    continue
                stem, ext = entry[:8].decode("ascii").rstrip(), entry[8:11].decode("ascii").rstrip()
                name = stem + ("." + ext if ext else "")
                if name in (".", ".."):
                    continue
                require(re.fullmatch(r"[A-Za-z0-9_. -]+", name) is not None and name.strip(". "),
                        "Unsupported or unsafe short filename")
                path = prefix + name
                first = struct.unpack_from("<H", entry, 26)[0]
                size = struct.unpack_from("<I", entry, 28)[0]
                if entry[11] & 0x10:
                    require(first not in visited, "FAT directory cluster reused")
                    visited.add(first)
                    walk(self.chain(first), path + "/", depth + 1)
                else:
                    require(path.casefold() not in {x.casefold() for x in result}, "Duplicate filename")
                    require(len(result) < 256 and size <= MAX_VOLUME, "FAT file limit exceeded")
                    data = self.chain(first)[:size] if size else b""
                    require(len(data) == size, "Truncated FAT file")
                    result[path] = data

        walk(self.data[self.root_offset:self.root_offset + self.root_bytes])
        return result


# Full-line matches avoid exposing serials, ECIDs, panel identifiers, bootargs,
# or arbitrary neighboring text from raw firmware logs.
LOG_ALLOWLIST = [
    r"S - Secure Boot: (?:On|Off)",
    r"UEFI Ver\s*:\s*[A-Za-z0-9._-]+",
    r"Build Info\s*:\s*64b (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}",
    r"(?:PROD Mode|Retail)\s*:\s*(?:TRUE|FALSE)",
    r"INFO: UEFI NV tables are enabled as VOLATILE!",
    r"POST Time\s*\[\s*\d+\]\s*OS Loader",
    r"Loader Build Info: (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}",
    r"VB: RWDeviceState: Succeed using rpmb!",
    r"Booting from slot \(_[ab]\)",
    r"Booting Into Mission Mode",
    r"VB2: Authenticate complete! boot state is: (?:orange|green|yellow|red)",
    r"VB2: boot state: (?:orange|green|yellow|red)\(\d+\)",
    r"KeyMasterSetRotAndBootState Set (?:RoT|Boot State) success",
    r"Shutting Down UEFI Boot Services: \d+ ms",
    r"Start EBS\s*\[\s*\d+\]",
]


def selected_log_lines(data):
    lines = data.rstrip(b"\0").decode("utf-8", errors="replace").splitlines()
    selected = []
    for number, original in enumerate(lines, 1):
        line = re.sub(r"^\[\d+\]\s*", "", original.strip())
        if any(re.fullmatch(pattern, line) for pattern in LOG_ALLOWLIST):
            selected.append({"line": number, "text": original.strip()})
    header = lines[0].strip() if lines and re.fullmatch(
        r"=== Dump occured at \d{4}-\d{2}-\d{2} \d{1,2}:\d{2}:\d{2} ===\s*", lines[0]) else None
    return {"line_count": len(lines), "dump_header": header, "selected_lines": selected}


def fv_headers(data):
    rows = []
    for origin, blob in expanded_blobs(data):
        for match in re.finditer(b"_FVH", blob):
            base = match.start() - 40
            if base < 0 or base + 56 > len(blob):
                continue
            length = struct.unpack_from("<Q", blob, base + 32)[0]
            header = struct.unpack_from("<H", blob, base + 48)[0]
            ext = struct.unpack_from("<H", blob, base + 52)[0]
            if not (56 <= header <= length <= len(blob) - base and header % 2 == 0):
                continue
            checksum = sum(struct.unpack_from("<" + "H" * (header // 2), blob, base)) & 0xFFFF
            name = str(uuid.UUID(bytes_le=blob[base + ext:base + ext + 16])) if ext and ext + 20 <= length else None
            rows.append({"origin": origin, "buffer_offset": hex(base), "fv_length": hex(length),
                         "header_length": hex(header), "header_checksum_valid": checksum == 0,
                         "filesystem_guid": str(uuid.UUID(bytes_le=blob[base + 16:base + 32])),
                         "fv_name_guid": name})
    return rows


def entry_relationships(tools, firmware_archive, output):
    """Cross-check the two namespaces and pinned BDS ordering against gpt.zip."""
    with zipfile.ZipFile(firmware_archive) as archive:
        uefi = read_member(archive, "cn/uefi.elf")
    require(sha256(uefi) == "1488a82e6735698f84bf0dcf05894723fba5cc2656fa1ed14dd91776b623481a",
            "Entry trace requires the original identified CN UEFI")
    images = {sha256(p.data): p.data for p in pe_images(uefi)}
    qcombds_hash = "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78"
    require(qcombds_hash in images, "QcomBds hash differs")
    qcombds = images[qcombds_hash]
    view = View(qcombds)
    actual_guid = str(uuid.UUID(bytes_le=qcombds[0x1D0E8:0x1D0F8]))
    require(actual_guid == "046fae99-cf2e-49ed-a6a8-a1488b7e80d3", "ABL dispatch namespace differs")
    tool_guid = "c4be3b58-1c19-4881-b101-8d02fce6708b"
    require(any(row["fv_name_guid"] == tool_guid for row in fv_headers(tools)), "Tools FV namespace differs")
    ebl = next(file for file, name, _ in named_firmware_files(tools) if name == "Ebl")
    tools_ebl = pe_images(ebl.data)[0].data
    main_ebl_images = {}
    for _, blob in expanded_blobs(uefi):
        for file, name, _ in named_firmware_files(blob):
            if name == "Ebl":
                for image in pe_images(file.data):
                    main_ebl_images[sha256(image.data)] = image.data
    require(len(main_ebl_images) == 1, "Main-UEFI Ebl UI name/PE is ambiguous")
    ebl_pe = next(iter(main_ebl_images.values()))
    require(sha256(ebl_pe) in images, "Main-UEFI Ebl extraction differs")
    marker = uuid.UUID(tool_guid).bytes_le
    references = [hex(m.start()) for m in re.finditer(re.escape(marker), ebl_pe)]
    require(references, "Tools FV GUID marker missing from Ebl")
    help_text = b"eg: MountFv toolsfv."
    help_offset = ebl_pe.find(help_text)
    require(help_offset >= 0, "MountFv help marker missing from main Ebl")
    calls = []
    for off, target in [(0x1DEC, 0x4FF4), (0x5254, 0x7D2C), (0x1E70, 0x56E4)]:
        instruction = view.instructions(off, 4)[0]
        require(instruction.mnemonic == "bl" and instruction.op_str == f"#0x{target:x}", "BDS call differs")
        calls.append(view.row(instruction))
    write_json(output / "entry_relationships.json", {
        "qcombds_sha256": qcombds_hash, "abl_dispatch_fv_guid": actual_guid,
        "tools_inner_fv_guid": tool_guid, "namespaces_differ": actual_guid != tool_guid,
        "main_uefi_ebl_sha256": sha256(ebl_pe), "tools_ebl_sha256": sha256(tools_ebl),
        "ebl_identical_in_main_uefi_and_toolsfv": tools_ebl == ebl_pe,
        "tools_guid_file_offsets_in_ebl": references, "direct_call_evidence": calls,
        "main_ebl_mountfv_help": {"file_offset": hex(help_offset), "text": help_text.decode()},
        "oem_setup_handler": view.rows(0x56E4, 0xA4),
        "limitations": ["GUID markers do not prove mounting or invoking the Tools FV",
                        "Default-app dispatch precedes the later setup handler on the documented path",
                        "No new pre-LinuxLoader entry has been runtime-tested"],
    })


def analyze(archive_path, manifest_path, output, firmware_archive=None):
    manifest = json.loads(manifest_path.read_text())
    with zipfile.ZipFile(archive_path) as archive:
        inputs = {name: read_member(archive, name) for name in manifest["files"]}
    for name, data in inputs.items():
        require(len(data) == manifest["files"][name]["size"] and
                sha256(data) == manifest["files"][name]["sha256"], "Private input differs: " + name)

    fat = Fat12(inputs["logfs-fat12.bin"])
    files = fat.files()
    logs = {}
    for name, data in files.items():
        if re.fullmatch(r"UEFILOG[0-9]\.TXT", name):
            logs[name] = {"size": len(data), "sha256": sha256(data), **selected_log_lines(data)}
    require(len(logs) == 5, "Expected five identified UEFI logs")
    write_json(output / "logfs.json", {
        "capture_sha256": sha256(inputs["logfs-fat12.bin"]), "bpb": fat.metadata,
        "files": [{"path": name, "size": len(data), "sha256": sha256(data)}
                  for name, data in sorted(files.items())], "logs": logs,
        "privacy": "Only allowlisted complete log lines are included; raw files stay private",
    })

    tools = inputs["toolsfv.bin"]
    inventory = []
    for file, name, guid in named_firmware_files(tools):
        if name:
            row = {"name": name, "ffs_guid": guid, "file_type": hex(file.type)}
            if file.type == 9:
                images = pe_images(file.data)
                require(len(images) == 1, "Expected one PE for tools application " + name)
                row["pe"] = images[0].metadata()
            inventory.append(row)
    app_count = sum(row["file_type"] == "0x9" for row in inventory)
    require(app_count == 19, "ToolsFV application inventory changed")
    write_json(output / "toolsfv.json", {
        "partition_read_bytes": len(tools), "sha256": sha256(tools),
        "firmware_volumes": fv_headers(tools), "named_files": inventory,
        "application_count": app_count,
        "execution_proven": False,
    })
    xbl = inputs["xbl_sc_logs.bin"]
    markers = [{"file_offset": hex(m.start()), "counter": int(m.group(1))}
               for m in re.finditer(rb"LOG_START-([0-9]{10})", xbl)]
    unique = sorted({m["counter"] for m in markers})
    failure_pattern = rb"(?i)(?:auth[^\r\n\0]{0,30}fail|invalid elf|not an elf|pil[^\r\n\0]{0,40}(?:fail|error)|ABL[^\r\n\0]{0,40}(?:fail|error))"
    write_json(output / "xbl.json", {
        "size": len(xbl), "sha256": sha256(xbl), "magic": xbl[:4].decode("ascii"),
        "marker_occurrences": markers, "unique_marker_counters": unique,
        "targeted_failure_pattern": failure_pattern.decode("ascii"),
        "targeted_failure_matches": len(list(re.finditer(failure_pattern, xbl))),
        "scope": "Absence of these strings is not a diagnosis of an earlier failed boot",
    })
    probe = json.loads(inputs["probe.json"])
    bootconfig = next(row["selected"] for row in probe["paths"] if row["path"] == "/proc/bootconfig")
    write_json(output / "summary.json", {
        "capture_date_jakarta": manifest["capture_date_jakarta"], "uid": probe["uid"],
        "captured_utc": probe["captured_utc"], "bootconfig_selected": bootconfig,
        "logfs_volume_bytes": fat.metadata["volume_bytes"], "logfs_partition_bytes_from_prior_gpt": 8388608,
        "uefi_log_count": len(logs), "toolsfv_applications": app_count,
        "shell_and_ebl_present": all(any(row["name"] == name for row in inventory) for name in ("Shell", "Ebl")),
        "hardware_writes_or_reboots": False, "custom_efi_entry_tested": False,
        "raw_firmware_or_logs_exported_by_analyzer": False,
    })
    if firmware_archive:
        entry_relationships(tools, firmware_archive, output)
    print("PASS: pinned capture hashes; FAT12 bounds, matching FATs and five complete UEFI logs")
    print("PASS: toolsfv inventory; native applications include Shell and Ebl")
    print("PASS: public evidence contains only metadata and allowlisted log lines")
    print("NOT TESTED: invoking Shell/GBL before LinuxLoader or accepting modified firmware")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Private live capture ZIP")
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).resolve().parents[1] / "LIVE_INPUTS.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, help="Optional original gpt.zip for namespace/BDS cross-check")
    args = parser.parse_args()
    analyze(args.archive, args.manifest, args.out, args.firmware)


if __name__ == "__main__":
    main()
