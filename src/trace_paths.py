#!/usr/bin/env python3
"""Trace the supplied boot container, FV namespace, and BDS dependencies.

All addresses are tied to identified input hashes. GUID-byte occurrences are
evidence of a binary reference, not proof of an installed protocol or ABI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import uuid
import zipfile
from pathlib import Path

import capstone
import pefile

from fwlib import (expanded_blobs, largest_pe, named_firmware_files, pe_images,
                   read_member, sha256, write_json)

ABL_FV_NAME = "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"
QCOMBDS_SHA256 = "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78"
UPSTREAM_COMMIT = "4ef438cfde42943694fde5753bbf5d8c0b4ec02e"


def elf32_headers(raw: bytes):
    if raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected little-endian ELF32 version 1")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", raw)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    if phentsize != 32 or phoff + phentsize * phnum > len(raw):
        raise ValueError("Invalid ELF program-header table")
    result = []
    for i in range(phnum):
        values = struct.unpack_from("<8I", raw, phoff + i * phentsize)
        kind, offset, va, pa, size, memsize, flags, align = values
        if offset + size > len(raw):
            raise ValueError("ELF segment outside input")
        result.append({"index": i, "type": kind, "offset": offset,
                       "virtual_address": va, "physical_address": pa,
                       "size": size, "memory_size": memsize,
                       "flags": flags, "alignment": align})
    return result


def audit_hash_segment(raw: bytes):
    headers = elf32_headers(raw)
    # The Qualcomm segment-type field is in p_flags bits 26:24.
    hash_segments = [x for x in headers if ((x["flags"] >> 24) & 7) == 2]
    matches = []
    for payload in headers:
        if payload["type"] != 1:
            continue
        data = raw[payload["offset"]:payload["offset"] + payload["size"]]
        for algorithm in ("sha256", "sha384"):
            digest = hashlib.new(algorithm, data).digest()
            for segment in hash_segments:
                block = raw[segment["offset"]:segment["offset"] + segment["size"]]
                for found in re.finditer(re.escape(digest), block):
                    matches.append({
                        "payload_segment": payload["index"], "algorithm": algorithm,
                        "digest": digest.hex(), "hash_segment": segment["index"],
                        "digest_file_offset": hex(segment["offset"] + found.start()),
                    })
    prefixes = [{"file_offset": hex(x["offset"]),
                 "first_96_bytes_hex": raw[x["offset"]:x["offset"] + 96].hex()}
                for x in hash_segments]
    return {"headers": headers, "digest_matches": matches,
            "hash_segment_prefixes": prefixes,
            "interpretation": "A matching digest does not establish signing-key ownership or runtime acceptance"}


def instruction_bytes(data: bytes, addresses):
    pe = pefile.PE(data=data, fast_load=True)
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    rows = []
    for rva in addresses:
        offset = pe.get_offset_from_rva(rva)
        raw = data[offset:offset + 4]
        insn = next(decoder.disasm(raw, rva), None)
        rows.append({"rva": hex(rva), "file_offset": hex(offset),
                     "bytes_hex": raw.hex(),
                     "mnemonic": insn.mnemonic if insn else None,
                     "operands": insn.op_str if insn else None})
    return rows


def fv_names(raw: bytes):
    rows = []
    for origin, data in expanded_blobs(raw):
        for match in re.finditer(b"_FVH", data):
            start = match.start() - 0x28
            if start < 0 or start + 0x38 > len(data):
                continue
            length = struct.unpack_from("<Q", data, start + 0x20)[0]
            ext = struct.unpack_from("<H", data, start + 0x34)[0]
            if length < 0x38 or start + length > len(data):
                continue
            name = None
            if ext and ext + 20 <= length:
                name = str(uuid.UUID(bytes_le=data[start + ext:start + ext + 16]))
            rows.append({"origin": origin, "offset": hex(start),
                         "size": length, "extension_offset": hex(ext),
                         "fv_name_guid": name})
    return rows


def declared_protocols(upstream: Path):
    edk = upstream / "submodules/uefi/edk2"
    infs = [
        edk / "QcomModulePkg/Application/LinuxLoader/LinuxLoader.inf",
        edk / "QcomModulePkg/Library/FastbootLib/FastbootLib.inf",
    ]
    names, active = [], False
    for inf in infs:
        active = False
        for line in inf.read_text().splitlines():
            if line.startswith("["):
                active = line.lower() == "[protocols]"
            if active:
                name = line.split("#", 1)[0].strip()
                if re.fullmatch(r"g\w+", name) and name not in names:
                    names.append(name)
    files = subprocess.check_output(
        ["rg", "--files", "-g", "*.dec", str(edk)], text=True).splitlines()
    pattern = re.compile(r"(?m)^\s*(g\w+)\s*=\s*\{([^{}]*)\{([^{}]*)\}\s*\}")
    declarations = {}
    for filename in files:
        text = Path(filename).read_text(errors="replace")
        for match in pattern.finditer(text):
            name = match[1]
            if name not in names:
                continue
            head = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", match[2])]
            tail = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", match[3])]
            if len(head) == 3 and len(tail) == 8:
                raw = struct.pack("<IHH8B", *head, *tail)
                declarations.setdefault(name, {})[raw] = str(Path(filename).relative_to(upstream))
    return names, declarations


def protocol_occurrences(names, declarations, modules, reference_bds):
    rows = []
    for name in names:
        variants = []
        for raw, source in declarations.get(name, {}).items():
            found = [label for label, blob in modules.items() if raw in blob]
            variants.append({"guid": str(uuid.UUID(bytes_le=raw)), "source": source,
                             "sm8750_uefi_modules_containing_guid": found,
                             "reference_bds_contains_guid": raw in reference_bds})
        rows.append({"name": name, "variants": variants})
    return {"scope": "Protocols declared by pinned upstream LinuxLoader.inf and FastbootLib.inf; not a complete transitive build dependency inventory",
            "warning": "Byte occurrence is not proof of protocol installation, revision, method layout, or runtime availability",
            "version_note": "The supplied module BDS binary and pinned upstream source are separate snapshots; a GUID missing from the old binary does not disprove use by current source",
            "protocols": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    current = subprocess.check_output(
        ["git", "-C", str(args.upstream), "rev-parse", "HEAD"], text=True).strip()
    if current != UPSTREAM_COMMIT:
        raise ValueError("Upstream revision differs from the documented snapshot")
    args.out.mkdir(parents=True, exist_ok=True)
    report = {"upstream_commit": current, "archive_sha256": sha256(args.archive.read_bytes())}
    with zipfile.ZipFile(args.archive) as archive:
        for tag, prefix in (("cn", "cn"), ("eng", "eng rom")):
            abl = read_member(archive, f"{prefix}/abl.elf")
            files = []
            for ff, name, guid in named_firmware_files(abl):
                if name:
                    files.append({"ui_name": name, "ffs_guid": guid,
                                  "ffs_type": ff.type})
            report[tag] = {"abl_sha256": sha256(abl), "firmware_volumes": fv_names(abl),
                           "named_ffs_files": files, "container": audit_hash_segment(abl)}
        uefi = read_member(archive, "cn/uefi.elf")
        modules = {}
        qcombds = None
        for ff, name, guid in named_firmware_files(uefi):
            for section in ff.sections:
                if section.type == 0x10:
                    modules[name or guid] = section.data
                    if name == "QcomBds":
                        qcombds = section.data
        if qcombds is None or sha256(qcombds) != QCOMBDS_SHA256:
            raise ValueError("QcomBds build does not match the traced offsets")
        fv_guid = str(uuid.UUID(bytes_le=qcombds[0x1D0E8:0x1D0F8]))
        if fv_guid != ABL_FV_NAME:
            raise ValueError("Unexpected dispatch FV GUID")
        report["dispatch"] = {
            "qcombds_sha256": sha256(qcombds), "fv_argument_data_rva": "0x1d0e8",
            "fv_argument_guid": fv_guid,
            "launch_helper_rva": "0x7d2c", "launch_callsite_rva": "0x5254",
            "guided_fv_comparison_rva": "0x7e78-0x7e8c",
            "file_path_lookup_callsite_rva": "0x7ee0",
            "load_image_callsite_rva": "0x7f30", "start_image_callsite_rva": "0x8040",
            "fv_argument_bytes_hex": qcombds[0x1D0E8:0x1D0F8].hex(),
            "instruction_bytes": instruction_bytes(qcombds, [
                0x1FA8, 0x1DEC, 0x50E0, 0x510C, 0x5254, 0x5258,
                0x7E84, 0x7E8C, 0x7EE0, 0x7F2C, 0x7F30, 0x803C, 0x8040]),
            "namespace_note": "The launch selects a named firmware volume; changing a UI name alone does not add a file to that volume",
        }
        module_zip = read_member(archive, "magisk_module.zip")
        import io
        with zipfile.ZipFile(io.BytesIO(module_zip)) as reference:
            bds = read_member(reference, "BDS.efi")
        names, declarations = declared_protocols(args.upstream)
        protocols = protocol_occurrences(names, declarations, modules, bds)
        write_json(args.out / "protocol_inventory.json", protocols)
        write_json(args.out / "boot_container_trace.json", report)
        table = ["# Deklarasi protokol BDS dan penanda pada firmware SM8750", "",
                 "Inventaris statis; kolom modul tidak membuktikan protokol terpasang atau ABI kompatibel.", "",
                 "| Nama | GUID | Modul SM8750 yang memuat byte GUID | Ada pada BDS referensi |",
                 "|---|---|---|---|"]
        for row in protocols["protocols"]:
            if not row["variants"]:
                table.append(f"| `{row['name']}` | belum terurai | belum dinilai | belum dinilai |")
            for variant in row["variants"]:
                found = ", ".join(variant["sm8750_uefi_modules_containing_guid"]) or "tidak ditemukan"
                present = "ya" if variant["reference_bds_contains_guid"] else "tidak"
                table.append(f"| `{row['name']}` | `{variant['guid']}` | {found} | {present} |")
        (args.out / "PROTOCOLS.md").write_text("\n".join(table) + "\n")
    print(json.dumps({
        "fv_guid_matches_dispatch_for_both_builds": all(any(
            x["fv_name_guid"] == fv_guid for x in report[tag]["firmware_volumes"])
            for tag in ("cn", "eng")),
        "payload_digest_matches": {tag: report[tag]["container"]["digest_matches"]
                                   for tag in ("cn", "eng")},
        "declared_protocol_count": len(protocols["protocols"]),
        "unresolved_protocol_declarations": [x["name"] for x in protocols["protocols"]
                                             if not x["variants"]],
    }, indent=2))


if __name__ == "__main__":
    main()
