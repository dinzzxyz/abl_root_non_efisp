#!/usr/bin/env python3
"""Map two identified SM8750 ABL payloads offline; emit evidence, never firmware.

The engineering candidate must reproduce the user's existing result exactly.
The CN candidate is a static analogy, not a validated bootloader patch or port.
"""
from __future__ import annotations

import argparse
import re
import struct
import zipfile
from pathlib import Path

import pefile
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

from fwlib import largest_pe, read_member, sha256, write_json

KNOWN_IMAGES = {
    "75e9d6122d708948c6a5f0b9774a061aa25ebb7a279fbe020ad8835400b065d2": "cn",
    "6270557b012660bd4d876a68368321d17a08efdb2e5a7d931a9f99346da736c7": "eng",
}
SUPPLIED_RESULT_SHA256 = "d7456c0e5d6d102cad963ea9c27f4b5fc3c999d6ebce5ade058efd52c352ef83"

# The reference patcher scans this byte mask at every byte offset. This is data
# from core.c at the pinned upstream revision, not a signature for our builds.
UPSTREAM_MASK = "??0000342800805206000014e8??40f9080140391f010071e8079f1a08791f53"
SOURCE_TEMPLATE = bytes.fromhex("bf5a00f9a08203ada08204ad")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def one(values, description):
    require(len(values) == 1, f"Expected one {description}, found {len(values)}")
    return values[0]


def reg(instruction, index):
    operand = instruction.operands[index]
    return instruction.reg_name(operand.reg) if operand.type == ARM64_OP_REG else None


def same_register(a, b):
    return a is not None and b is not None and a.lstrip("wx") == b.lstrip("wx")


def immediate(instruction, index):
    operand = instruction.operands[index]
    return operand.imm if operand.type == ARM64_OP_IMM else None


def memory(instruction, index):
    operand = instruction.operands[index]
    if operand.type != ARM64_OP_MEM:
        return None
    return (instruction.reg_name(operand.mem.base), operand.mem.disp,
            instruction.reg_name(operand.mem.index) if operand.mem.index else None)


class View:
    """Keep raw file offsets and PE RVAs separate, including for branch targets."""

    def __init__(self, data):
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=True)
        require(self.pe.FILE_HEADER.Machine == 0xAA64, "Expected ARM64 PE")
        require(self.pe.OPTIONAL_HEADER.ImageBase == 0, "Only image-base-zero PEs audited")
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True
        self.code = [(s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData)
                     for s in self.pe.sections if s.Characteristics & 0x20000000]

    def rva(self, offset):
        return self.pe.get_rva_from_offset(offset)

    def offset(self, rva):
        return self.pe.get_offset_from_rva(rva)

    def instructions(self, offset, size):
        return list(self.md.disasm(self.data[offset:offset + size], self.rva(offset)))

    def executable(self, offset, size=4):
        return any(a <= offset and offset + size <= b for a, b in self.code)

    def offsets(self, size=4):
        for start, end in self.code:
            yield from range((start + 3) & ~3, end - size + 1, 4)

    def row(self, instruction):
        return {"file_offset": hex(self.offset(instruction.address)),
                "rva": hex(instruction.address), "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic, "operands": instruction.op_str}

    def rows(self, offset, size):
        return [self.row(i) for i in self.instructions(offset, size)]

    def cstring(self, rva):
        try:
            offset = self.offset(rva)
            end = self.data.index(b"\0", offset, offset + 128)
            return self.data[offset:end].decode("ascii")
        except (ValueError, UnicodeDecodeError, pefile.PEFormatError):
            return None


def find_bootstate_blocks(view):
    """Match instruction roles AND both branch destinations, not just bytes.

    These builds use TST/B.EQ and a direct LDRB, whereas upstream expects CBZ
    and an extra stack-based LDR. Registers and branch encodings are decoded.
    """
    matches = []
    for off in view.offsets(32):
        word = struct.unpack_from("<I", view.data, off)[0]
        if word & ~0x3E0 != 0x72001C1F:  # TST Wn, #0xff
            continue
        ins = view.instructions(off, 32)
        if len(ins) != 8 or [i.mnemonic for i in ins] != [
                "tst", "b.eq", "mov", "b", "ldrb", "cmp", "cset", "lsl"]:
            continue
        tested, state = reg(ins[0], 0), reg(ins[2], 0)
        if not (tested == state and immediate(ins[0], 1) == 255 and
                immediate(ins[1], 0) == ins[4].address and
                immediate(ins[2], 1) == 1 and
                immediate(ins[3], 0) == ins[-1].address + 4 and
                reg(ins[4], 0) == state and memory(ins[4], 1) is not None and
                reg(ins[5], 0) == state and immediate(ins[5], 1) == 0 and
                reg(ins[6], 0) == state and ins[6].op_str.endswith(", ne") and
                reg(ins[7], 0) == state and reg(ins[7], 1) == state and
                immediate(ins[7], 2) == 1):
            continue
        prefix = view.instructions(off - 4, 4)
        if (len(prefix) == 1 and prefix[0].mnemonic == "ldr" and
                same_register(reg(prefix[0], 0), tested) and
                memory(prefix[0], 1) is not None and memory(prefix[0], 1)[0] == "sp"):
            matches.append({"offset": off, "instructions": ins,
                            "stack_load": prefix[0], "state_register": state,
                            "stack_slot": memory(prefix[0], 1)[1]})
    return matches


def adrl(view, offset):
    if not view.executable(offset, 8):
        return None
    ins = view.instructions(offset, 8)
    if len(ins) != 2 or [i.mnemonic for i in ins] != ["adrp", "add"]:
        return None
    if not (reg(ins[0], 0) == reg(ins[1], 0) == reg(ins[1], 1) and
            immediate(ins[1], 2) is not None and ins[1].operands[2].shift.value == 0):
        return None
    return immediate(ins[0], 1) + immediate(ins[1], 2), reg(ins[0], 0)


def adrl_pairs(view):
    for off in view.offsets(8):
        word = struct.unpack_from("<I", view.data, off)[0]
        if word & 0x9F000000 != 0x90000000:
            continue
        pair = adrl(view, off)
        if pair:
            yield off, pair


def encode_adrl(pc_rva, target_rva, register):
    rd = int(register.removeprefix("x"))
    delta = (target_rva >> 12) - (pc_rva >> 12)
    require(-(1 << 20) <= delta < 1 << 20 and 0 <= rd < 31, "ADRP out of range")
    imm = delta & ((1 << 21) - 1)
    page = 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd
    add = 0x91000000 | ((target_rva & 0xFFF) << 10) | (rd << 5) | rd
    return struct.pack("<II", page, add)


def find_string_dispatch(view, pairs):
    matches = []
    for off, (target, register) in pairs:
        if view.cstring(target) != "unlocked":
            continue
        locked = adrl(view, off + 8)
        if not locked or locked[1] == register or view.cstring(locked[0]) != "locked":
            continue
        keys = [j for j in range(off + 16, off + 44, 4)
                if adrl(view, j) and view.cstring(adrl(view, j)[0]) ==
                "androidboot.vbmeta.device_state"]
        if len(keys) == 1:
            matches.append((off, target, locked[0], register, keys[0]))
    return matches


def find_source(view):
    found = []
    for match in re.finditer(re.escape(SOURCE_TEMPLATE), view.data):
        off = match.start() + len(SOURCE_TEMPLATE)
        if not view.executable(off - 12, 12 + 16):
            continue
        ins = view.instructions(off, 16)
        if (len(ins) == 4 and [i.mnemonic for i in ins] == ["bl", "movi", "tst", "mov"]
                and reg(ins[2], 0) == "w0" and immediate(ins[2], 1) == 255
                and reg(ins[3], 1) == "w0"):
            found.append((off, view.offset(immediate(ins[0], 0)), reg(ins[3], 0)))
    return found


def find_local_sink(view, block):
    """Find a local uninterrupted stack reload -> STRB, with register checks.

    This verifies only this basic-block fragment. It does not prove which
    earlier stack definition reaches the reload on every path.
    """
    candidates = []
    start = block["offset"] + 32
    ins = view.instructions(start, 0xA0)
    for index, load in enumerate(ins):
        if load.mnemonic != "ldr" or memory(load, 1) != ("sp", block["stack_slot"], None):
            continue
        source = reg(load, 0)
        for sink in ins[index + 1:]:
            if sink.mnemonic == "strb" and same_register(source, reg(sink, 0)):
                mem = memory(sink, 1)
                if mem and mem[0] == "sp" and mem[2] is None:
                    candidates.append((load, sink))
                break
            if sink.mnemonic in ("bl", "blr", "br", "b", "ret") or sink.mnemonic.startswith("b."):
                break
            if any(same_register(source, sink.reg_name(r)) for r in sink.regs_access()[1]):
                break
    return candidates


def upstream_mask_offsets(data):
    pattern = b"".join(b"[\\s\\S]" if UPSTREAM_MASK[i:i + 2] == "??" else
                       re.escape(bytes.fromhex(UPSTREAM_MASK[i:i + 2]))
                       for i in range(0, len(UPSTREAM_MASK), 2))
    return [m.start() for m in re.finditer(pattern, data)]


def analyze_image(data):
    digest = sha256(data)
    require(digest in KNOWN_IMAGES, "Unknown PE hash; no candidate recipe is emitted")
    view = View(data)
    blocks = find_bootstate_blocks(view)
    block = one(blocks, "structural boot-state block")
    state_store = view.instructions(block["offset"] + 36, 4)[0]
    require(state_store.mnemonic == "str" and reg(state_store, 0) == block["state_register"]
            and memory(state_store, 1) == ("x19", 0x438, None), "Boot-state output store differs")
    sources = find_source(view)
    source, getter, saved_register = one(sources, "initial getter callsite")
    sink_load, sink = one(find_local_sink(view, block), "local stack reload/byte-store sink")
    pairs = list(adrl_pairs(view))
    off, unlocked, locked, register, key = one(find_string_dispatch(view, pairs),
                                               "vbmeta device-state string dispatch")

    # Infer the global byte read by the getter, and independently locate an
    # initialization site comparing the containing structure's 13-byte magic.
    getter_ins = view.instructions(getter, 0x2C)
    byte_load = one([i for i in getter_ins if i.mnemonic == "ldrb" and reg(i, 0) == "w0"],
                    "getter return-byte load")
    mem = memory(byte_load, 1)
    page = one([i for i in getter_ins if i.mnemonic == "adrp" and reg(i, 0) == mem[0]],
               "getter global-page reference")
    field_rva = immediate(page, 1) + mem[1]
    base_rva = field_rva - 13
    magic_off, _ = one([(a, p) for a, p in pairs if view.cstring(p[0]) == "ANDROID-BOOT!"],
                       "DeviceInfo magic address pair")
    magic_helper = magic_off - 4
    helper = view.instructions(magic_helper, 20)
    require(len(helper) == 5 and helper[0].mnemonic == "mov" and
            reg(helper[0], 0) == "w2" and immediate(helper[0], 1) == 13 and
            helper[-1].mnemonic == "ret", "Unexpected magic-argument helper")
    init_matches = []
    for address, pair in pairs:
        if pair[0] != base_rva:
            continue
        following = view.instructions(address + 8, 8)
        if (len(following) == 2 and following[0].mnemonic == "bl" and
                immediate(following[0], 0) == view.rva(magic_helper) and
                following[1].mnemonic == "bl"):
            init_matches.append(address)
    init = one(init_matches, "DeviceInfo base/magic initialization sequence")

    def edit(at, replacement, reason):
        return {"file_offset": hex(at), "rva": hex(view.rva(at)),
                "before": data[at:at + len(replacement)].hex(),
                "after": replacement.hex(), "reason": reason}

    mov = block["instructions"][2]
    mov_raw = struct.unpack("<I", mov.bytes)[0]
    require((mov_raw >> 5) & 0xFFFF == 1, "Unexpected MOV immediate encoding")
    sink_raw = struct.unpack("<I", sink.bytes)[0]
    edits = [edit(source, bytes.fromhex("20008052"), "replace getter call with MOV W0,#1"),
             edit(view.offset(mov.address), struct.pack("<I", mov_raw & ~(0xFFFF << 5)),
                  "replace selected state's MOV immediate 1 with 0"),
             edit(view.offset(sink.address), struct.pack("<I", (sink_raw & ~31) | 31),
                  "replace local STRB source with WZR"),
             edit(off, encode_adrl(view.rva(off), locked, register),
                  "point first string address pair to locked")]
    candidate = bytearray(data)
    for item in edits:
        at = int(item["file_offset"], 16)
        candidate[at:at + len(bytes.fromhex(item["after"]))] = bytes.fromhex(item["after"])
    if KNOWN_IMAGES[digest] == "eng":
        require(sha256(candidate) == SUPPLIED_RESULT_SHA256,
                "Structural calibration did not reproduce the engineering oracle")
    report = {
        "build": KNOWN_IMAGES[digest], "input_pe_sha256": digest,
        "input_pe_size": len(data), "image_base": hex(view.pe.OPTIONAL_HEADER.ImageBase),
        "status": "STATIC_CANDIDATE_NOT_DEVICE_VALIDATED", "hardware_execution": False,
        "counts": {"upstream_mask_hits": len(upstream_mask_offsets(data)),
                   "structural_bootstate_hits": len(blocks), "source_template_hits": len(sources),
                   "local_sink_hits": 1, "device_state_string_dispatch_hits": 1},
        "bootstate": {"test_rva": hex(view.rva(block["offset"])),
                      "stack_slot": hex(block["stack_slot"]),
                      "state_register": block["state_register"],
                      "output_store": view.row(state_store),
                      "instructions": view.rows(block["offset"] - 4, 48)},
        "source": {"call_rva": hex(view.rva(source)), "getter_rva": hex(view.rva(getter)),
                   "saved_register": saved_register, "instructions": view.rows(source - 12, 36),
                   "getter_instructions": view.rows(getter, 0x2C)},
        "deviceinfo": {"field_rva": hex(field_rva), "base_rva": hex(base_rva),
                       "field_offset_from_base": 13,
                       "symbol": "IsUnlocked / DeviceInfo.is_unlocked (source-informed inference)",
                       "initialization": view.rows(init, 24),
                       "magic_argument_helper": view.rows(magic_helper, 20)},
        "local_sink": {"reload": view.row(sink_load), "store": view.row(sink),
                       "instructions": view.rows(view.offset(sink_load.address),
                                                 sink.address - sink_load.address + 4),
                       "scope": "local uninterrupted fragment; no full interprocedural or alias proof"},
        "strings": {"unlocked_rva": hex(unlocked), "locked_rva": hex(locked),
                    "key_pair_rva": hex(view.rva(key)), "instructions": view.rows(off, 40)},
        "candidate_edits": edits, "candidate_pe_sha256": sha256(candidate),
        "changed_byte_count": sum(a != b for a, b in zip(data, candidate)),
        "candidate_container_created": False,
        "limitations": ["No ABL ELF/FV repack, signature acceptance, or runtime test",
                        "No GBL entry or SuperFastboot implementation is added",
                        "Local stack provenance is not a full control-flow/alias proof",
                        "Only the two exact input hashes are accepted"],
    }
    return report, bytes(candidate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Original gpt.zip")
    parser.add_argument("--out", type=Path, required=True, help="Evidence directory (text/JSON only)")
    args = parser.parse_args()
    reports = {}
    with zipfile.ZipFile(args.archive) as archive:
        supplied = read_member(archive, "result/boot.efi")
        for tag, member in (("cn", "cn/abl.elf"), ("eng", "eng rom/abl.elf")):
            original = largest_pe(read_member(archive, member)).data
            report, candidate = analyze_image(original)
            require(report["build"] == tag, "Archive build label does not match identified PE")
            if tag == "eng":
                require(candidate == supplied, "Candidate differs from supplied engineering result")
                report["byte_identical_to_supplied_result"] = True
            reports[tag] = report
            write_json(args.out / f"{tag}_bootstate_map.json", report)
            snippets = []
            for name, rows in (("source", report["source"]["instructions"]),
                               ("getter", report["source"]["getter_instructions"]),
                               ("DeviceInfo initialization", report["deviceinfo"]["initialization"]),
                               ("magic arguments", report["deviceinfo"]["magic_argument_helper"]),
                               ("boot state", report["bootstate"]["instructions"]),
                               ("local sink", report["local_sink"]["instructions"]),
                               ("device-state strings", report["strings"]["instructions"])):
                snippets.append(f"\n{name}: file offsets and PE RVAs are listed separately")
                snippets.extend((f"file {r['file_offset']:>9} / RVA {r['rva']:>9}: "
                                 f"{r['bytes']:<16} {r['mnemonic']:<7} {r['operands']}").rstrip()
                                for r in rows)
            (args.out / f"{tag}_bootstate_trace.txt").write_text("\n".join(snippets).lstrip() + "\n")
            print(f"{tag}: one structural block, {report['changed_byte_count']} candidate byte changes")
    write_json(args.out / "summary.json", {
        "method": "Decode role/branch anchors; calibrate against supplied engineering result",
        "upstream_revision": "4ef438cfde42943694fde5753bbf5d8c0b4ec02e",
        "deviceinfo_reference_repo": "https://github.com/REG-Linux/edk2-freeabl",
        "deviceinfo_reference_revision": "4cd7fb389e22d7a3761308006fc6d79410be9ddf",
        "deviceinfo_reference_blobs": {"QcomModulePkg/Include/Library/DeviceInfo.h":
                                       "09f596b7c2273be27f65325949fb543d5e57e4ac",
                                       "QcomModulePkg/Library/BootLib/DeviceInfo.c":
                                       "a2f80542ebcadecf9e8b7b4adfcf15e0e8e57956"},
        "engineering_calibration": "byte-identical to supplied result/boot.efi",
        "cn_runtime_validation": False, "firmware_files_written": False,
        "input_hashes": {tag: report["input_pe_sha256"] for tag, report in reports.items()},
    })
    print("PASS: engineering calibration matches every byte of the supplied result")
    print("NOT TESTED: CN runtime, image authentication, GBL entry, or SuperFastboot")


if __name__ == "__main__":
    main()
