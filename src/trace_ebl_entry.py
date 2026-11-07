#!/usr/bin/env python3
"""Audit the identified native Ebl RAM/file routes and QcomBds callback order.

Offline only. Outputs metadata and selected disassembly, never a firmware image.
Fixed offsets are accepted only after matching the complete PE SHA-256.
"""
from __future__ import annotations

import argparse
import struct
import uuid
import zipfile
from pathlib import Path

from capstone.arm64 import ARM64_OP_MEM

from fwlib import pe_images, read_member, sha256, write_json
from map_bootstate import View, immediate, memory, reg, require

QCOMBDS_SHA256 = "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78"
EBL_SHA256 = "306bed8aaca6c2a31b6bee8360d1e9c727440ed50664bf3e107420ec103c5761"
PIL_SHA256 = "a9a04094e1685e5cbd06a2fe287da560410bd93852096be12d4d49c7f2ba82b6"
UEFI_SHA256 = "1488a82e6735698f84bf0dcf05894723fba5cc2656fa1ed14dd91776b623481a"
DXE_GUID = "05ad34ba-6f02-4214-952e-4da0398e2bb9"


def address_references(view):
    """Conservative local ADRP/ADD/MOV tracking, including interleaved ADRPs.

    Forget values at calls, branches, branch destinations, invalid instructions,
    section gaps and register writes. This is a local xref helper, not a CFG or
    global dataflow proof. Decode each aligned word so embedded data cannot stop
    disassembly of the rest of an executable section.
    """
    instructions = {}
    targets = set()
    for off in view.offsets():
        decoded = view.instructions(off, 4)
        if not decoded:
            continue
        ins = decoded[0]
        instructions[off] = ins
        if (ins.mnemonic in {"b", "bl", "cbz", "cbnz", "tbz", "tbnz"}
                or ins.mnemonic.startswith("b.")):
            target = immediate(ins, len(ins.operands) - 1)
            if target is not None:
                targets.add(target)
    known, output, previous = {}, [], None
    for off in view.offsets():
        ins = instructions.get(off)
        if ins is None:
            known, previous = {}, None
            continue
        if previous is None or off != previous + 4 or ins.address in targets:
            known = {}
        previous = off
        updates = {}
        if ins.mnemonic == "adrp":
            updates[reg(ins, 0)] = immediate(ins, 1)
        elif (ins.mnemonic == "add" and len(ins.operands) == 3
              and reg(ins, 1) in known and immediate(ins, 2) is not None
              and reg(ins, 0).startswith("x")):
            updates[reg(ins, 0)] = known[reg(ins, 1)] + (
                immediate(ins, 2) << ins.operands[2].shift.value)
            output.append({**view.row(ins), "kind": "address",
                           "target_rva": hex(updates[reg(ins, 0)])})
        elif (ins.mnemonic == "mov" and len(ins.operands) == 2
              and reg(ins, 1) in known and reg(ins, 0).startswith("x")):
            updates[reg(ins, 0)] = known[reg(ins, 1)]
        for operand in ins.operands:
            if operand.type != ARM64_OP_MEM or operand.mem.index:
                continue
            base = ins.reg_name(operand.mem.base)
            if base in known:
                output.append({**view.row(ins), "kind": "memory",
                               "target_rva": hex(known[base] + operand.mem.disp)})
        for register in ins.regs_access()[1]:
            name = ins.reg_name(register)
            known.pop(name, None)
            if name.startswith("w"):
                known.pop("x" + name[1:], None)
        known.update(updates)
        if (ins.mnemonic in {"b", "bl", "blr", "br", "ret", "cbz", "cbnz",
                             "tbz", "tbnz"} or ins.mnemonic.startswith("b.")):
            known = {}
    return output


def resolve_table_thunk(view, table_rva, field, max_hops=8):
    """Resolve a PE table qword and bounded unconditional-branch thunks."""
    off = view.offset(table_rva + field)
    require(0 <= off <= len(view.data) - 8, "Protocol table outside PE")
    pointer = struct.unpack_from("<Q", view.data, off)[0]
    current, seen, chain = pointer, set(), []
    for _ in range(max_hops):
        require(current not in seen, "Loop in protocol thunk")
        seen.add(current)
        location = view.offset(current)
        require(view.executable(location), "Protocol pointer outside executable PE")
        decoded = view.instructions(location, 4)
        require(len(decoded) == 1, "Invalid protocol thunk")
        ins = decoded[0]
        if ins.mnemonic == "b":
            chain.append(view.row(ins))
            current = immediate(ins, 0)
            continue
        return {"field_offset": hex(field), "pointer_rva": hex(pointer),
                "target_rva": hex(current), "thunks": chain}
    raise ValueError("Protocol thunk depth limit")


def expect_call(view, offset, target):
    ins = view.instructions(offset, 4)[0]
    require(ins.mnemonic == "bl" and immediate(ins, 0) == target,
            f"Unexpected call at file offset {offset:#x}")
    return view.row(ins)


def table_entry(view, offset, handler, marker):
    values = struct.unpack_from("<4Q", view.data, offset)
    name, help_text = view.cstring(values[0]), view.cstring(values[1])
    require(values[3] == handler and name and marker in name,
            "Unexpected Ebl registration")
    return {"file_offset": hex(offset), "rva": hex(view.rva(offset)),
            "bytes": view.data[offset:offset + 32].hex(), "name": name,
            "help": help_text, "handler_rva": hex(handler)}


def analyze(qcombds, ebl):
    require(sha256(qcombds) == QCOMBDS_SHA256, "Unknown QcomBds PE hash")
    require(sha256(ebl) == EBL_SHA256, "Unknown main UEFI Ebl PE hash")
    b, e = View(qcombds), View(ebl)
    brefs, erefs = address_references(b), address_references(e)
    guid = str(uuid.UUID(bytes_le=b.data[0x1d278:0x1d288]))
    require(guid == "d874d61a-4b87-7608-a00f-58add7052530", "Protocol GUID differs")
    require(struct.unpack_from("<Q", b.data, 0x1d460)[0] == 0x10003,
            "Protocol revision differs")
    callbacks = [resolve_table_thunk(b, 0x1d460, x) for x in range(8, 0x40, 8)]
    require([x["target_rva"] for x in callbacks] == [
        "0x62ac", "0x162c", "0x69a8", "0x6a38", "0x59dc", "0x6ba4", "0x69c8"],
        "Protocol callback table differs")
    require(any(x["file_offset"] == "0x2478" and x["target_rva"] == "0x1d460"
                for x in brefs), "Protocol installer interface xref missing")
    order = b.rows(0x1d84, 0x6c)
    callsites = {int(x["file_offset"], 16): x for x in order}
    require(callsites[0x1dc0]["mnemonic"] == "blr" and
            memory(b.instructions(0x1dbc, 4)[0], 1)[1] == 0x28,
            "Early hotkey callback differs")
    bds = {
        "sha256": sha256(qcombds), "address_space": "PE file offsets and RVAs, not ELF offsets",
        "protocol_guid": guid, "protocol_guid_rva": "0x1d278",
        "interface_rva": "0x1d460", "interface_revision": "0x10003",
        "installer": b.rows(0x2468, 0x24), "callbacks": callbacks,
        "console_wrapper_call": expect_call(b, 0x1634, 0x65f0),
        "early_order": order,
        "default_call": expect_call(b, 0x1dec, 0x4ff4),
        "linuxloader_launch": expect_call(b, 0x5254, 0x7d2c),
        "later_setup_call": expect_call(b, 0x1e70, 0x56e4),
        "hotkey_variable": b.data[0x1762c:0x1762c + 28].decode("utf-16le").rstrip("\0"),
        "os_indications_name": b.data[0x175e4:0x175e4 + 28].decode("utf-16le").rstrip("\0"),
        "hotkey_path_calls": [expect_call(b, a, t) for a, t in [
            (0x5a8c, 0xa184), (0x5abc, 0x4a50), (0x5b14, 0x6f38),
            (0x5b50, 0x8690), (0x1dcc, 0x6cdc)]],
        "findings": [
            "The local installed platform protocol has a hotkey callback before default apps.",
            "The examined early callback records attention, reads OEMSetupApp, and returns success.",
            "Its call to 0x6f38 is a SerialPort Lib operation, not an Ebl launch.",
            "The separate setup-app launch at 0x56e4 is called after default apps return.",
            "No stock pre-LinuxLoader Ebl invocation has been established by this audit."],
        "local_address_refs": [x for x in brefs if int(x["target_rva"], 16) in {
            0x1d278, 0x1d460, 0x17b22, 0x17b30}],
    }
    require(str(uuid.UUID(bytes_le=e.data[0x19028:0x19038])) == DXE_GUID,
            "DXE Services GUID differs")
    for site, target in [(0x4128, 0x19028), (0x412c, 0x1ae30),
                         (0x87b0, 0x19028), (0x87b4, 0x1ae68)]:
        require(any(x["file_offset"] == hex(site) and x["target_rva"] == hex(target)
                    for x in erefs), "DXE Services constructor reference missing")
    expect_call(e, 0x4130, 0x86c0)
    expect_call(e, 0x87b8, 0x86c0)
    for site in [0x3588, 0x35cc]:
        require(memory(e.instructions(site, 4)[0], 1) == ("x8", 0x98, None),
                "ProcessFirmwareVolume service field differs")
        require(e.instructions(site + 4, 4)[0].mnemonic == "blr",
                "ProcessFirmwareVolume indirect call missing")
    fv = {
        "sha256": sha256(ebl), "ffs_type": 9, "pe_subsystem": e.pe.OPTIONAL_HEADER.Subsystem,
        "address_space": "PE file offsets and RVAs, not UEFI ELF offsets",
        "registrations": [table_entry(e, a, h, s) for a, h, s in [
            (0x14040, 0x3534, "loadfv"), (0x14060, 0x3374, "start"),
            (0x176d8, 0xdc94, "mountfv")]],
        "dxe_services_guid": DXE_GUID, "guid_rva": "0x19028",
        "dxe_services_constructors": e.rows(0x4120, 0x14) + e.rows(0x87a8, 0x14),
        "loadfv_file_read": expect_call(e, 0x35a4, 0xd2c8),
        "loadfv_ram_calls": e.rows(0x3578, 0x18) + e.rows(0x35b8, 0x1c),
        "process_firmware_volume_field": "0x98", "dxe_dispatch_field": "0x80",
        "mountfv_file_calls": [expect_call(e, a, t) for a, t in [
            (0xdd74, 0xd2c8), (0xdd84, 0x1305c), (0x130f4, 0xb830),
            (0xb8c4, 0xb56c), (0xde18, 0x13124), (0xde20, 0x10e64)]],
        "mountfv_help": [{"rva": hex(a), "text": e.cstring(a)}
                         for a in [0x15f9f, 0x15fd3, 0x15fe9, 0x16020]],
        "nested_fv_install": e.rows(0xb7d4, 0x3c),
        "nested_fv_protocol_guid": str(uuid.UUID(bytes_le=e.data[0x19128:0x19138])),
        "start_load_image": e.rows(0x3410, 0x24),
        "start_image": e.rows(0x34d8, 0x18),
        "findings": [
            "loadfv reads a file or device buffer and calls DXE Services ProcessFirmwareVolume.",
            "mountfv -f reads a file and recursively processes nested FVs with a local FVB installer.",
            "mountfv also accepts partition labels and -g GUID selection; paths differ from loadfv.",
            "mountfv's common tail reconnects controllers and calls DXE Dispatch.",
            "start uses Boot Services LoadImage and StartImage; authentication acceptance is untested.",
            "FV mounting, driver dispatch, and starting a type-9 application are separate operations.",
            "Ebl is a type-9 application, so its presence alone is not a preboot entry mechanism."],
        "custom_efi_entry_tested": False, "hardware_writes_or_reboots": False,
    }
    return bds, fv


def disassembly(view, windows):
    lines = ["# file_offset | RVA | bytes | instruction; identified PE only"]
    for start, end in windows:
        lines.append(f"\n# PE file range {start:#x}..{end:#x} (end exclusive)")
        for row in view.rows(start, end - start):
            lines.append((f'{row["file_offset"]} | {row["rva"]} | {row["bytes"]} | '
                          f'{row["mnemonic"]} {row["operands"]}').rstrip())
    return "\n".join(lines) + "\n"


def pil_binding(qcombds, pil):
    """Bind the ABL pre-load consumer to the installed PILDxe protocol table."""
    require(sha256(qcombds) == QCOMBDS_SHA256, "Unknown QcomBds PE hash")
    require(sha256(pil) == PIL_SHA256, "Unknown PILDxe PE hash")
    b, p = View(qcombds), View(pil)
    guid = uuid.UUID("1f4f1da3-4d8d-4894-ba2a-13d3207f9739").bytes_le
    require(b.data[0x1d288:0x1d298] == p.data[0x170c8:0x170d8] == guid,
            "PIL protocol GUID binding differs")
    require(struct.unpack_from("<Q", p.data, 0x171b8)[0] == 0x10005 and
            struct.unpack_from("<Q", p.data, 0x171c0)[0] == 0x1790,
            "PIL interface revision or first method differs")
    refs = address_references(p)
    require(any(x["file_offset"] == "0x1734" and x["target_rva"] == "0x171b8"
                for x in refs), "PIL installer interface reference missing")
    argument = b.data[0x17600:0x17608].decode("utf-16le").rstrip("\0")
    require(argument == "ABL", "PIL consumer argument differs")
    require(b.instructions(0x4f4c, 4)[0].mnemonic == "blr" and
            memory(b.instructions(0x4f48, 4)[0], 1) == ("x8", 8, None),
            "PIL consumer method call differs")
    return {"qcombds_pe_sha256": sha256(qcombds), "pildxe_pe_sha256": sha256(pil),
            "address_space": "Offsets/RVAs in each named PE, not UEFI ELF offsets",
            "protocol_guid": str(uuid.UUID(bytes_le=guid)),
            "consumer_guid_rva": "0x1d288", "producer_guid_rva": "0x170c8",
            "producer_interface_rva": "0x171b8", "producer_interface_revision": "0x10005",
            "interface_method_0x08_target_rva": "0x1790",
            "producer_install": p.rows(0x1724, 0x28),
            "consumer_call": b.rows(0x4f14, 0x40),
            "consumer_argument": argument, "consumer_argument_rva": "0x17600",
            "method_wrapper": p.rows(0x1790, 0x24),
            "method_wrapper_helper_call": expect_call(p, 0x1798, 0x1fc0),
            "interpretation": "The examined pre-default ABL load call uses PILDxe, not a newly found Ebl launcher",
            "ebl_entry_established": False, "runtime_image_authentication_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--out", type=Path, default=Path("generated/entry"))
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        uefi = read_member(archive, "cn/uefi.elf")
    require(sha256(uefi) == UEFI_SHA256, "Unknown CN UEFI container hash")
    images = {sha256(p.data): p.data for p in pe_images(uefi)}
    bds, fv = analyze(images[QCOMBDS_SHA256], images[EBL_SHA256])
    write_json(args.out / "bds_entry.json", bds)
    write_json(args.out / "ebl_ram_fv.json", fv)
    write_json(args.out / "pil_binding.json", pil_binding(images[QCOMBDS_SHA256], images[PIL_SHA256]))
    for name, digest, windows in [
        ("bds_entry", QCOMBDS_SHA256, [(0x1d44, 0x1e88), (0x2468, 0x248c),
          (0x1628, 0x1658), (0x59dc, 0x5b80), (0x6cdc, 0x6d80),
          (0x6e50, 0x6f4c), (0x56e4, 0x5828)]),
        ("ebl_ram_fv", EBL_SHA256, [(0x3374, 0x3534), (0x3534, 0x35fc),
          (0x4118, 0x4148), (0x86c0, 0x879c), (0x879c, 0x880c),
          (0xdc94, 0xde24), (0x1305c, 0x13224), (0xb7d4, 0xb810),
          (0xb830, 0xb954), (0x10e64, 0x10f3c)])]:
        (args.out / (name + ".disasm.txt")).write_text(
            disassembly(View(images[digest]), windows))
    print("PASS: native Ebl RAM/file routes and QcomBds callback order reproduced offline")
    print("NOT TESTED: pre-LinuxLoader Ebl entry, custom image authentication or execution")


if __name__ == "__main__":
    main()
