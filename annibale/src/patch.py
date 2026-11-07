#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce the OS3.0.307.0.WPKCNXM ABL research candidate, offline only.

This preserves the ELF/FV layout and updates checksums and the payload digest.
It does NOT create an OEM signature, add a GBL entry, or invoke fastboot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import struct
import tempfile
from pathlib import Path

NAME = "OS3.0.307.0.WPKCNXM_abl.elf"
STOCK_SHA256 = "d6e9b4111652bc0067547994a3f8396541383e093aee5d74b154e88f82342309"
STOCK_PE_SHA256 = "75e9d6122d708948c6a5f0b9774a061aa25ebb7a279fbe020ad8835400b065d2"
PATCHED_PE_SHA256 = "9b55fb1ee70b3519a947160033d4d9929edf6d045d6dbc0c4e39b23fdf8fffc5"
PATCHED_ELF_SHA256 = "bbf89327ec2060f83d5e9ec068fd77d2fe2010caee865be176c835bb6dc3447a"
SIZE = 335672
PAYLOAD_START, PAYLOAD_END = 0x1000, 0x51000
OUTER_FFS, GUID_SECTION, STREAM = 0x1048, 0x1060, 0x1078
EXPANDED_SIZE, INNER_FV, APP_FFS, PE_START, PE_SIZE = 0x1200C8, 8, 0x80, 0xB8, 0x120000
HASH_TABLE, PAYLOAD_DIGEST, SIGNATURE_START, CERT_START = 0x51120, 0x51150, 0x511B0, 0x51218
EDITS = (
    (0x3A398, "37a9ff97", "20008052", "BL getter -> MOV W0,#1"),
    (0x3B774, "28008052", "08008052", "MOV W8,#1 -> MOV W8,#0"),
    (0x3B7B8, "ea030139", "ff030139", "STRB W10 -> STRB WZR, [SP,#0x40]"),
    (0x45674, "e90200b029b12391", "6902009029253991", "address unlocked -> locked"),
)
FILTER = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 24, "lc": 3, "lp": 0,
          "pb": 2, "mode": lzma.MODE_NORMAL, "nice_len": 273, "mf": lzma.MF_BT4,
          "depth": 0}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def uint24(data, offset):
    require(0 <= offset <= len(data) - 3, "24-bit field outside input")
    return int.from_bytes(data[offset:offset + 3], "little")


def put24(data, offset, value):
    require(0 <= value < 0xFFFFFF, "Unsupported section/file size")
    require(0 <= offset <= len(data) - 3, "24-bit field outside output")
    data[offset:offset + 3] = value.to_bytes(3, "little")


def check_fv(data, offset, expected_size):
    require(offset + 0x38 <= len(data), "Truncated FV header")
    require(data[offset + 0x28:offset + 0x2C] == b"_FVH", "FV signature mismatch")
    length = struct.unpack_from("<Q", data, offset + 0x20)[0]
    header_length = struct.unpack_from("<H", data, offset + 0x30)[0]
    require(length == expected_size and offset + length <= len(data), "FV extent mismatch")
    require(0x38 <= header_length <= length and header_length % 2 == 0,
            "Invalid FV header length")
    words = struct.unpack_from("<" + str(header_length // 2) + "H", data, offset)
    require(sum(words) & 0xFFFF == 0, "FV header checksum mismatch")


def check_ffs(data, offset, expected_type):
    require(offset + 24 <= len(data), "Truncated FFS header")
    length = uint24(data, offset + 20)
    require(24 <= length < 0xFFFFFF and offset + length <= len(data), "FFS extent mismatch")
    require(data[offset + 18] == expected_type and data[offset + 19] == 0,
            "Unexpected FFS type/attributes; only this checksum-disabled layout is audited")
    header = bytearray(data[offset:offset + 24])
    header[17] = header[23] = 0
    require(sum(header) & 0xFF == 0, "FFS header checksum mismatch")
    require(data[offset + 17] == 0xAA, "Expected fixed FFS data checksum 0xAA")
    return length


def check_elf(data):
    require(len(data) == SIZE, "ELF size mismatch")
    require(data[:7] == b"\x7fELF\x01\x01\x01", "Expected ELF32 little-endian container")
    h = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    require(h[2] == 40 and h[4] == 0x9FA00000 and h[5] == 0x34 and
            h[9:11] == (32, 3), "Unexpected ARM ELF/program header layout")
    expected = [(0, 0, 0, 0, 0x94, 0, 0x07000000, 0),
                (1, 0x1000, 0x9FA00000, 0x9FA00000, 0x50000, 0x50000, 7, 0x1000),
                (0, 0x51000, 0, 0, 0xF38, 0xF38, 0x02000000, 0x1000)]
    actual = [struct.unpack_from("<8I", data, 0x34 + i * 32) for i in range(3)]
    require(actual == expected, "Program headers differ from the audited input")
    mbn = struct.unpack_from("<16I", data, PAYLOAD_END)
    require(mbn == (0, 7, 24, 0, 224, 144, 0, 0, 104, 3360, 0, 0, 28, 0, 3, 0),
            "MBNv7 header/common metadata mismatch")
    require(hashlib.sha384(data[:0x94]).digest() == data[HASH_TABLE:PAYLOAD_DIGEST],
            "ELF header SHA-384 mismatch")
    require(hashlib.sha384(data[PAYLOAD_START:PAYLOAD_END]).digest() ==
            data[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48], "Payload SHA-384 mismatch")
    require(data[PAYLOAD_DIGEST + 48:SIGNATURE_START] == bytes(48),
            "Hash-segment placeholder digest differs")


def unpack_payload(data):
    check_fv(data, PAYLOAD_START, 0x50000)
    outer_size = check_ffs(data, OUTER_FFS, 0x0B)
    section_size = uint24(data, GUID_SECTION)
    require(data[GUID_SECTION + 3] == 2 and section_size + 24 == outer_size,
            "GUID-defined section extent/type mismatch")
    require(data[GUID_SECTION + 4:STREAM] == bytes.fromhex(
        "98584eee143959429d6edc7bd79403cf18000100"), "LZMA section GUID/header mismatch")
    stream_end = GUID_SECTION + section_size
    require(STREAM < stream_end <= PAYLOAD_END, "Compressed payload outside PT_LOAD")
    require(data[stream_end:PAYLOAD_END] == b"\xFF" * (PAYLOAD_END - stream_end),
            "Unexpected non-erased tail after the compressed section")
    stream = data[STREAM:stream_end]
    require(stream[:13] == bytes.fromhex("5d00000001c800120000000000"),
            "LZMA properties/declared output length differ")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64 << 20)
    expanded = decoder.decompress(stream, max_length=EXPANDED_SIZE + 1)
    require(decoder.eof and not decoder.unused_data and len(expanded) == EXPANDED_SIZE,
            "LZMA stream is truncated, oversized or has unused bytes")
    check_fv(expanded, INNER_FV, 0x1200C0)
    check_ffs(expanded, APP_FFS, 9)
    require(expanded[PE_START - 4:PE_START] == bytes.fromhex("04001210") and
            expanded[PE_START:PE_START + 2] == b"MZ", "PE section layout differs")
    return expanded, len(stream)


def rebuild(stock):
    require(sha256(stock) == STOCK_SHA256, "Unknown stock ELF SHA-256; refusing to patch")
    check_elf(stock)
    original, old_stream_size = unpack_payload(stock)
    require(sha256(original[PE_START:PE_START + PE_SIZE]) == STOCK_PE_SHA256,
            "Stock LinuxLoader PE hash mismatch")
    expanded = bytearray(original)
    changes = []
    for offset, before, after, description in EDITS:
        a, b = bytes.fromhex(before), bytes.fromhex(after)
        require(len(a) == len(b), "Patch changes instruction range length")
        location = PE_START + offset
        require(expanded[location:location + len(a)] == a, "Original instruction mismatch")
        expanded[location:location + len(a)] = b
        changes.append({"pe_file_offset": hex(offset), "pe_rva": hex(offset),
                        "expanded_buffer_offset": hex(location), "before": before,
                        "after": after, "description": description})
    require(sum(a != b for a, b in zip(original, expanded)) == 10,
            "Unexpected changed-byte count in expanded payload")
    require(sha256(expanded[PE_START:PE_START + PE_SIZE]) == PATCHED_PE_SHA256,
            "Patched PE differs from the prior research candidate")
    check_fv(expanded, INNER_FV, 0x1200C0)
    check_ffs(expanded, APP_FFS, 9)
    packed = lzma.compress(bytes(expanded), format=lzma.FORMAT_ALONE, filters=[FILTER])
    # liblzma writes an unknown length; the OEM section declares the exact length.
    packed = packed[:5] + len(expanded).to_bytes(8, "little") + packed[13:]
    require(STREAM + len(packed) <= PAYLOAD_END, "Recompressed FV exceeds PT_LOAD capacity")
    result = bytearray(stock)
    result[STREAM:PAYLOAD_END] = packed + b"\xFF" * (PAYLOAD_END - STREAM - len(packed))
    put24(result, GUID_SECTION, len(packed) + 24)
    put24(result, OUTER_FFS + 20, len(packed) + 48)
    header = bytearray(result[OUTER_FFS:OUTER_FFS + 24])
    header[16] = header[17] = header[23] = 0
    result[OUTER_FFS + 16] = (-sum(header)) & 0xFF
    result[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48] = hashlib.sha384(
        result[PAYLOAD_START:PAYLOAD_END]).digest()
    result = bytes(result)
    require(sha256(result) == PATCHED_ELF_SHA256,
            "Rebuilt ELF differs from pinned result; check liblzma/recipe before publishing")
    check_elf(result)
    decoded, new_stream_size = unpack_payload(result)
    require(decoded == expanded, "Re-extracted payload differs after repacking")
    require(result[:PAYLOAD_START] == stock[:PAYLOAD_START] and
            result[PAYLOAD_END:PAYLOAD_DIGEST] == stock[PAYLOAD_END:PAYLOAD_DIGEST] and
            result[PAYLOAD_DIGEST + 48:] == stock[PAYLOAD_DIGEST + 48:],
            "Unexpected change outside payload and its digest")
    report = {
        "device": "annibale", "build": "OS3.0.307.0.WPKCNXM",
        "status": "RESEARCH CANDIDATE; NOT OEM-RESIGNED; NO RUNTIME BOOT TEST",
        "stock_elf_sha256": sha256(stock), "patched_elf_sha256": sha256(result),
        "elf_size": len(result), "stock_pe_sha256": STOCK_PE_SHA256,
        "patched_pe_sha256": PATCHED_PE_SHA256, "pe_size": PE_SIZE,
        "pe_changed_byte_count": 10, "edits": changes,
        "elf_payload_file_offset": hex(PAYLOAD_START), "elf_payload_size": 0x50000,
        "lzma_file_offset": hex(STREAM), "stock_lzma_size": old_stream_size,
        "patched_lzma_size": new_stream_size, "expanded_size": len(expanded),
        "expanded_pe_offset": hex(PE_START), "compression": FILTER,
        "outer_ffs_header_checksum": hex(result[OUTER_FFS + 16]),
        "fv_and_ffs_header_checksums_valid": True,
        "elf_program_headers_preserved": True, "payload_digest_file_offset": hex(PAYLOAD_DIGEST),
        "payload_sha384": result[PAYLOAD_DIGEST:PAYLOAD_DIGEST + 48].hex(),
        "oem_signed_range": [hex(PAYLOAD_END), hex(SIGNATURE_START)],
        "oem_signature_file_offset": hex(SIGNATURE_START), "oem_signature_size": 104,
        "oem_signature_and_certificates_preserved": True, "oem_signature_regenerated": False,
        "oem_signed_bytes_changed": stock[PAYLOAD_END:SIGNATURE_START] != result[PAYLOAD_END:SIGNATURE_START],
        "signature_verification": "Run src/verify_signature.py; retaining OEM bytes does not re-sign changed data",
        "gbl_or_superfastboot_entry_added": False, "hardware_writes_or_reboots": False,
    }
    return result, report


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=root / "src" / NAME)
    parser.add_argument("--output", type=Path, default=root / NAME)
    parser.add_argument("--report", type=Path, default=root / "build-report.json")
    parser.add_argument("--check", action="store_true", help="Compare existing output/report without writing")
    args = parser.parse_args()
    require(len({p.resolve() for p in [args.input, args.output, args.report]}) == 3,
            "Input, output and report must be different files")
    result, report = rebuild(args.input.read_bytes())
    report_bytes = (json.dumps(report, indent=2) + "\n").encode()
    if args.check:
        require(args.output.read_bytes() == result, "Existing output is not byte-identical to this rebuild")
        require(args.report.read_bytes() == report_bytes, "Existing build report differs")
        print("PASS: output ELF and report reproduce byte-for-byte")
    else:
        for path, data in [(args.output, result), (args.report, report_bytes)]:
            require(not path.exists() or path.read_bytes() == data,
                    "Refusing to overwrite a different existing file: " + str(path))
        atomic_write(args.output, result)
        atomic_write(args.report, report_bytes)
        print("BUILT:", args.output)
    print("SHA-256:", sha256(result))
    print("RESEARCH ONLY: OEM signature not regenerated; custom EFI entry and boot not demonstrated")


if __name__ == "__main__":
    main()
