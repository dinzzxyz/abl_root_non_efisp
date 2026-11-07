#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the pinned annibale UEFI Ebl-first experiment, offline only.

The hook belongs to QcomBds in UEFI, not LinuxLoader in ABL. This builds an
ELF/FV container with valid segment digests, NOT a new valid OEM signature.
Requires the adjacent patch.py helpers; no third-party dependency or device I/O.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import uuid
from pathlib import Path

import patch as support

require, sha256 = support.require, support.sha256
STOCK_NAME = "OS3.0.307.0.WPKCNXM_uefi.elf"
NAME = "OS3.0.307.0.WPKCNXM_uefi_EBL_FIRST_RESEARCH.elf"
STOCK_SHA256 = "1488a82e6735698f84bf0dcf05894723fba5cc2656fa1ed14dd91776b623481a"
PATCHED_ELF_SHA256 = "4d27c3300126e46e0f736a45d8899a02c9277baa4250d47744fcdb35abd112cd"
STOCK_PE_SHA256 = "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78"
PATCHED_PE_SHA256 = "6a2ae633b79c979dfffad7df8100c5c624fc52c5cc71601a16139f635a7da16e"
SIZE, PAYLOAD_START, PAYLOAD_END = 2839004, 0x1000, 0x2B4000
MAIN_FFS, GUID_SECTION, STREAM, NEXT_FFS = 0x4E238, 0x4E250, 0x4E268, 0xF14E0
EXPANDED_SIZE, INNER_FV, APP_FFS, PE_START, PE_SIZE = 0x41F008, 8, 0x3C18D0, 0x3C18F4, 0x20000
HASH_TABLE, PAYLOAD_DIGEST = 0x2B4120, 0x2B4150
SIGNATURE_START, CERT_START, CERT_END = 0x2B41B0, 0x2B4218, 0x2B4F38
CALL, STUB = 0x5254, 0x1C900  # PE raw offsets equal RVA at these pinned locations.
MAIN_GUID = "631008b0-b2d1-410a-8b49-2c5c4d8ecc7e"
ABL_GUID = "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"
STUB_HEX = (
    "fd7bbea9f35301a9f30300aaf40301aa"
    "000000b000e0039141010010e2031faa"
    "03adff97e00313aae10314aae2031faa"
    "ffacff97f35341a9fd7bc2a8c0035fd6"
    "450062006c000000"
)


def align8(value):
    return (value + 7) & ~7


def walk_ffs(data, fv, size):
    """Check the actual file chain, including PAD files and the erased tail."""
    support.check_fv(data, fv, size)
    header_length = struct.unpack_from("<H", data, fv + 0x30)[0]
    require(struct.unpack_from("<I", data, fv + 0x2C)[0] & 0x800,
            "Expected FV erase polarity 1")
    pos, end, files = fv + align8(header_length), fv + size, []
    while pos + 24 <= end and data[pos:pos + 24] != b"\xFF" * 24:
        length = support.uint24(data, pos + 20)
        attrs = data[pos + 19]
        require(not attrs & 1 and 24 <= length < 0xFFFFFF and pos + length <= end,
                "Unsupported or out-of-bounds FFS extent")
        header = bytearray(data[pos:pos + 24])
        header[17] = header[23] = 0
        require(sum(header) & 0xFF == 0, "FFS header checksum mismatch")
        require(data[pos + 23] == 0xF8, "Unexpected FFS file state")
        if attrs & 0x40:
            require((sum(data[pos + 24:pos + length]) + data[pos + 17]) & 0xFF == 0,
                    "FFS data checksum mismatch")
        else:
            require(data[pos + 17] == 0xAA, "Expected fixed FFS data checksum")
        files.append({"offset": hex(pos), "size": length, "type": hex(data[pos + 18]),
                      "guid": str(uuid.UUID(bytes_le=data[pos:pos + 16]))})
        pos = fv + align8(pos + length - fv)
    require(pos <= end and data[pos:end] == b"\xFF" * (end - pos),
            "Erased hole hides a later FFS file or tail is not erased")
    return files


def check_elf(data):
    require(len(data) == SIZE, "UEFI ELF size mismatch")
    require(data[:7] == b"\x7fELF\x02\x01\x01", "Expected ELF64 little-endian wrapper")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    require(h[2] == 40 and h[4] == 0xA7000000 and h[5] == 0x40 and
            h[9:11] == (56, 3), "Unexpected UEFI ELF/program header layout")
    expected = [(0, 0x07000000, 0, 0, 0, 0xE8, 0, 0),
                (1, 7, 0x1000, 0xA7000000, 0xA7000000, 0x2B3000, 0x2B3000, 0x1000),
                (0, 0x02000000, 0x2B4000, 0, 0, 0x11DC, 0x11DC, 0x1000)]
    require([struct.unpack_from("<IIQQQQQQ", data, 0x40 + i * 56) for i in range(3)] == expected,
            "Program headers differ from audited UEFI")
    require(struct.unpack_from("<16I", data, PAYLOAD_END) ==
            (0, 7, 24, 0, 224, 144, 0, 0, 104, 3360, 0, 0, 9, 0, 3, 0),
            "UEFI MBNv7 header/common metadata mismatch")
    require(hashlib.sha384(data[:0xE8]).digest() == data[HASH_TABLE:PAYLOAD_DIGEST],
            "UEFI ELF header SHA-384 mismatch")
    require(hashlib.sha384(data[PAYLOAD_START:PAYLOAD_END]).digest() ==
            data[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48], "UEFI payload SHA-384 mismatch")
    require(data[PAYLOAD_DIGEST + 48:SIGNATURE_START] == bytes(48),
            "Hash-segment placeholder digest differs")
    require(data[CERT_END:] == b"\xFF" * (len(data) - CERT_END),
            "Unexpected trailing UEFI hash-segment bytes")


def unpack_payload(data):
    outer = walk_ffs(data, PAYLOAD_START, PAYLOAD_END - PAYLOAD_START)
    length = support.check_ffs(data, MAIN_FFS, 0x0B)
    section_size = support.uint24(data, GUID_SECTION)
    require(section_size + 24 == length and data[GUID_SECTION + 3] == 2,
            "Main FV GUID-defined section extent/type differs")
    require(data[GUID_SECTION + 4:STREAM] == bytes.fromhex(
        "98584eee143959429d6edc7bd79403cf18000100"), "LZMA GUID-defined section differs")
    end = GUID_SECTION + section_size
    require(STREAM < end <= NEXT_FFS, "Main compressed stream overlaps the following FFS")
    stream = data[STREAM:end]
    require(stream[:13] == bytes.fromhex("5d0000000108f0410000000000"),
            "Main LZMA properties/length differ")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64 << 20)
    expanded = decoder.decompress(stream, max_length=EXPANDED_SIZE + 1)
    require(decoder.eof and not decoder.unused_data and len(expanded) == EXPANDED_SIZE,
            "Main LZMA stream is truncated, oversized or has trailing bytes")
    require(expanded[:8] == bytes.fromhex("0400001904f04117") and
            expanded[0x68:0x78] == uuid.UUID(MAIN_GUID).bytes_le,
            "Expanded FV wrapper/namespace differs")
    inner = walk_ffs(expanded, INNER_FV, EXPANDED_SIZE - INNER_FV)
    require(expanded[APP_FFS:APP_FFS + 16] ==
            uuid.UUID("5a50aa81-c3ae-4608-a0e3-41a2e69baf94").bytes_le and
            support.check_ffs(expanded, APP_FFS, 7) == 0x20038,
            "QcomBds FFS differs")
    require(expanded[PE_START - 4:PE_START] == bytes.fromhex("04000210") and
            expanded[PE_START:PE_START + 2] == b"MZ", "QcomBds PE section differs")
    require(len(inner) == 64 and any(x["offset"] == hex(NEXT_FFS) for x in outer),
            "Missing inner files or following outer FFS")
    return expanded, len(stream), outer


def rebuild(stock):
    require(sha256(stock) == STOCK_SHA256, "Unknown stock UEFI SHA-256; refusing to patch")
    check_elf(stock)
    original, old_size, old_files = unpack_payload(stock)
    original_pe = original[PE_START:PE_START + PE_SIZE]
    require(sha256(original_pe) == STOCK_PE_SHA256, "Stock QcomBds PE hash mismatch")
    stub = bytes.fromhex(STUB_HEX)
    require(len(stub) == 72 and sha256(stub) ==
            "c23fd7d7575070f8b87de2d7990ad95d856d407c7353aae25017c5c807d0f234",
            "Hook bytes differ from the emulated v7 program")
    require(original_pe[CALL:CALL + 4] == bytes.fromhex("b60a0094") and
            original_pe[STUB:STUB + len(stub)] == bytes(len(stub)),
            "Original launch instruction or candidate padding differs")
    for at, guid in [(0x1D0F8, MAIN_GUID), (0x1D0E8, ABL_GUID)]:
        require(original_pe[at:at + 16] == uuid.UUID(guid).bytes_le, "Launch FV GUID differs")
    expanded = bytearray(original)
    edits = [(CALL, original_pe[CALL:CALL + 4], bytes.fromhex("ab5d0094")),
             (STUB, bytes(len(stub)), stub)]
    for offset, before, after in edits:
        expanded[PE_START + offset:PE_START + offset + len(after)] = after
    patched_pe = expanded[PE_START:PE_START + PE_SIZE]
    require(sha256(patched_pe) == PATCHED_PE_SHA256, "Hooked QcomBds differs from the pinned plan")
    require(expanded[:PE_START] == original[:PE_START] and
            expanded[PE_START + PE_SIZE:] == original[PE_START + PE_SIZE:],
            "Unexpected change outside QcomBds PE")
    packed = lzma.compress(bytes(expanded), format=lzma.FORMAT_ALONE, filters=[support.FILTER])
    packed = packed[:5] + len(expanded).to_bytes(8, "little") + packed[13:]
    pad_start = align8(STREAM + len(packed))
    pad_size = NEXT_FFS - pad_start
    require(pad_size >= 24, "No room for a valid PAD FFS without moving the following file")
    result = bytearray(stock)
    result[STREAM:NEXT_FFS] = packed + b"\xFF" * (NEXT_FFS - STREAM - len(packed))
    support.put24(result, GUID_SECTION, len(packed) + 24)
    support.put24(result, MAIN_FFS + 20, len(packed) + 48)
    header = bytearray(result[MAIN_FFS:MAIN_FFS + 24])
    header[16] = header[17] = header[23] = 0
    result[MAIN_FFS + 16] = (-sum(header)) & 0xFF
    # A naked erased gap would terminate enumeration before NEXT_FFS. Insert
    # an ordinary PAD file with an erased body, following the original format.
    pad = bytearray(b"\xFF" * 16 + bytes([0, 0, 0xF0, 0]) + pad_size.to_bytes(3, "little") + b"\0")
    pad[16] = (-sum(pad)) & 0xFF
    pad[17], pad[23] = 0xAA, 0xF8
    result[pad_start:pad_start + 24] = pad
    result[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48] = hashlib.sha384(
        result[PAYLOAD_START:PAYLOAD_END]).digest()
    result = bytes(result)
    require(sha256(result) == PATCHED_ELF_SHA256,
            "UEFI output differs from pinned result; check compressor/recipe before publishing")
    require(result[:MAIN_FFS] == stock[:MAIN_FFS] and
            result[NEXT_FFS:PAYLOAD_DIGEST] == stock[NEXT_FFS:PAYLOAD_DIGEST] and
            result[PAYLOAD_DIGEST + 48:] == stock[PAYLOAD_DIGEST + 48:],
            "Unexpected change outside Main FV file region and its segment digest")
    check_elf(result)
    decoded, new_size, new_files = unpack_payload(result)
    require(decoded == expanded, "UEFI re-extraction differs after repack")
    require(len(old_files) == 5 and len(new_files) == 6 and
            result[pad_start + 24:NEXT_FFS] == b"\xFF" * (pad_size - 24),
            "PAD file or outer file-chain count differs")
    report = {
        "device": "annibale", "build": "OS3.0.307.0.WPKCNXM", "target_component": "UEFI / QcomBds, NOT ABL",
        "status": "EXPERIMENTAL CONTAINER; OEM SIGNATURE INVALID; NO DEVICE BOOT TEST",
        "stock_filename": STOCK_NAME, "candidate_filename": NAME,
        "stock_elf_sha256": sha256(stock), "patched_elf_sha256": sha256(result), "elf_size": len(result),
        "stock_qcombds_pe_sha256": STOCK_PE_SHA256, "patched_qcombds_pe_sha256": PATCHED_PE_SHA256,
        "qcombds_pe_size": PE_SIZE, "pe_changed_byte_count": sum(a != b for a, b in zip(original_pe, patched_pe)),
        "edits": [{"pe_file_offset": hex(at), "pe_rva": hex(at),
                   "expanded_buffer_offset": hex(PE_START + at), "size": len(a),
                   "before": a.hex(), "after": b.hex()} for at, a, b in edits],
        "stub_sha256": sha256(stub), "stub_padding_globally_proven_unused": False,
        "main_fv_guid": MAIN_GUID, "fallback_abl_fv_guid": ABL_GUID,
        "flow": ["Reach original QcomBds LinuxLoader call at RVA 0x5254 after charger/PIL preparation",
                 "Launch native Ebl in Main FV via helper RVA 0x7D2C",
                 "If Ebl returns, launch original LinuxLoader in ABL FV and return to RVA 0x5258"],
        "expanded_size": len(expanded), "expanded_qcombds_pe_offset": hex(PE_START),
        "expanded_sha256": sha256(expanded), "lzma_elf_file_offset": hex(STREAM),
        "stock_lzma_size": old_size, "patched_lzma_size": new_size, "compression": support.FILTER,
        "main_ffs_elf_file_offset": hex(MAIN_FFS), "main_ffs_size": len(packed) + 48,
        "main_ffs_header_checksum": hex(result[MAIN_FFS + 16]),
        "padding_ffs_elf_file_offset": hex(pad_start), "padding_ffs_size": pad_size,
        "padding_ffs_header_hex": pad.hex(), "outer_files_before": old_files, "outer_files_after": new_files,
        "following_ffs_elf_file_offset_preserved": hex(NEXT_FFS),
        "other_ffs_contents_and_offsets_preserved": True, "fv_and_ffs_checksums_valid": True,
        "elf_program_headers_preserved": True, "payload_digest_file_offset": hex(PAYLOAD_DIGEST),
        "payload_sha384": result[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48].hex(),
        "oem_signed_range": [hex(PAYLOAD_END), hex(SIGNATURE_START)],
        "oem_signature_file_offset": hex(SIGNATURE_START), "oem_signature_size": 104,
        "certificate_chain_file_range": [hex(CERT_START), hex(CERT_END)],
        "signature_certificates_and_trailing_bytes_preserved": True, "oem_signature_regenerated": False,
        "abl_modified": False, "new_superfastboot_payload_included": False,
        "runtime_efi_or_authentication_tested": False, "hardware_writes_or_reboots": False,
    }
    return result, report


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=root / "src" / STOCK_NAME)
    parser.add_argument("--output", type=Path, default=root / NAME)
    parser.add_argument("--report", type=Path, default=root / "uefi-ebl-first-build-report.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    require(len({p.resolve() for p in [args.input, args.output, args.report]}) == 3,
            "Input, output and report must be different files")
    result, report = rebuild(args.input.read_bytes())
    content = (json.dumps(report, indent=2) + "\n").encode()
    if args.check:
        require(args.output.read_bytes() == result, "Existing UEFI ELF differs from rebuild")
        require(args.report.read_bytes() == content, "Existing UEFI build report differs")
        print("PASS: experimental UEFI ELF and report reproduce byte-for-byte")
    else:
        for path, data in [(args.output, result), (args.report, content)]:
            require(not path.exists() or path.read_bytes() == data,
                    "Refusing to overwrite a different existing file: " + str(path))
        support.atomic_write(args.output, result)
        support.atomic_write(args.report, content)
        print("BUILT:", args.output)
    print("SHA-256:", sha256(result))
    print("RESEARCH ONLY: modified UEFI, not ABL; retained OEM signature INVALID; device execution NOT TESTED")


if __name__ == "__main__":
    main()
