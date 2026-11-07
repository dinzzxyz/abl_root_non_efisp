#!/usr/bin/env python3
"""Generate an offline Ebl-before-LinuxLoader hook study for one QcomBds hash.

Only a 72-byte new program, assembly listing and evidence are written. No OEM
PE/ELF, signed image, flash command, device write or runtime UEFI is produced.
"""
from __future__ import annotations

import argparse
import struct
import uuid
import zipfile
from pathlib import Path

from fwlib import (expanded_blobs, named_firmware_files, pe_images, read_member,
                   sha256, write_json)
from map_bootstate import View, encode_adrl, immediate, require
from trace_ebl_entry import QCOMBDS_SHA256, UEFI_SHA256

CALL_RVA, LAUNCH_RVA, STUB_RVA = 0x5254, 0x7D2C, 0x1C900
MAIN_GUID_RVA, ABL_GUID_RVA = 0x1D0F8, 0x1D0E8
MAIN_GUID = "631008b0-b2d1-410a-8b49-2c5c4d8ecc7e"
ABL_GUID = "046fae99-cf2e-49ed-a6a8-a1488b7e80d3"


def encode_bl(pc, target):
    delta = target - pc
    require(delta % 4 == 0 and -(1 << 27) <= delta < 1 << 27, "BL target outside aligned range")
    return struct.pack("<I", 0x94000000 | ((delta >> 2) & 0x3FFFFFF))


def encode_adr(pc, target, register):
    delta = target - pc
    require(-(1 << 20) <= delta < 1 << 20 and 0 <= register < 31, "ADR target/register outside range")
    value = delta & ((1 << 21) - 1)
    return struct.pack("<I", 0x10000000 | ((value & 3) << 29) | ((value >> 2) << 5) | register)


def build_stub():
    code = b"".join([
        bytes.fromhex("fd7bbea9"),       # stp x29,x30,[sp,#-32]!
        bytes.fromhex("f35301a9"),       # stp x19,x20,[sp,#16]
        bytes.fromhex("f30300aa"),       # mov x19,x0 : original ABL namespace
        bytes.fromhex("f40301aa"),       # mov x20,x1 : original LinuxLoader name
        encode_adrl(STUB_RVA + 16, MAIN_GUID_RVA, "x0"),
        encode_adr(STUB_RVA + 24, STUB_RVA + 64, 1),
        bytes.fromhex("e2031faa"),       # mov x2,xzr
        encode_bl(STUB_RVA + 32, LAUNCH_RVA),
        bytes.fromhex("e00313aa"),       # mov x0,x19
        bytes.fromhex("e10314aa"),       # mov x1,x20
        bytes.fromhex("e2031faa"),
        encode_bl(STUB_RVA + 48, LAUNCH_RVA),
        bytes.fromhex("f35341a9"),       # ldp x19,x20,[sp,#16]
        bytes.fromhex("fd7bc2a8"),       # ldp x29,x30,[sp],#32
        bytes.fromhex("c0035fd6"),
    ])
    require(len(code) == 64, "Unexpected hook instruction length")
    return code + "Ebl\0".encode("utf-16le")


def plan_for_pe(data):
    require(sha256(data) == QCOMBDS_SHA256, "Unknown QcomBds PE hash")
    view = View(data)
    call_offset, stub_offset = view.offset(CALL_RVA), view.offset(STUB_RVA)
    original = view.instructions(call_offset, 4)[0]
    require(original.mnemonic == "bl" and immediate(original, 0) == LAUNCH_RVA,
            "Original LinuxLoader call differs")
    require(view.data[view.offset(CALL_RVA - 4):call_offset] == bytes.fromhex("e2031faa"),
            "Original third argument is not NULL")
    stub = build_stub()
    require(view.executable(stub_offset, len(stub)) and
            data[stub_offset:stub_offset + len(stub)] == bytes(len(stub)),
            "Candidate executable padding is not zero-filled or outside the section")
    for rva, guid in [(MAIN_GUID_RVA, MAIN_GUID), (ABL_GUID_RVA, ABL_GUID)]:
        off = view.offset(rva)
        require(data[off:off + 16] == uuid.UUID(guid).bytes_le, "FV namespace GUID differs")
    refs = []
    for off in view.offsets():
        decoded = view.instructions(off, 4)
        if not decoded:
            continue
        ins = decoded[0]
        if ins.mnemonic in {"b", "bl", "cbz", "cbnz", "tbz", "tbnz"} or ins.mnemonic.startswith("b."):
            target = immediate(ins, len(ins.operands) - 1)
            if target is not None and STUB_RVA <= target < STUB_RVA + len(stub):
                refs.append(view.row(ins))
    pointers = [hex(off) for off in range(0, len(data) - 7, 8)
                if STUB_RVA <= struct.unpack_from("<Q", data, off)[0] < STUB_RVA + len(stub)]
    require(not refs and not pointers, "Static reference into the proposed padding")
    replacement = encode_bl(CALL_RVA, STUB_RVA)
    decoded = list(view.md.disasm(stub[:64], STUB_RVA))
    require(len(decoded) == 16 and decoded[8].mnemonic == decoded[12].mnemonic == "bl",
            "Hook does not decode as the intended 16 instructions")
    patched_memory = bytearray(data)
    patched_memory[call_offset:call_offset + 4] = replacement
    patched_memory[stub_offset:stub_offset + len(stub)] = stub
    return {
        "status": "OFFLINE HOOK STUDY; NOT A FLASHABLE OR AUTHENTICATED IMAGE",
        "qcombds_pe_sha256": sha256(data),
        "address_space": "QcomBds PE RVA and converted file offsets, not ABL/UEFI ELF offsets",
        "call_rva": hex(CALL_RVA), "call_file_offset": hex(call_offset),
        "original_call_bytes": data[call_offset:call_offset + 4].hex(),
        "proposed_call_bytes": replacement.hex(), "launch_helper_rva": hex(LAUNCH_RVA),
        "stub_rva": hex(STUB_RVA), "stub_file_offset": hex(stub_offset),
        "stub_size": len(stub), "stub_instruction_count": len(decoded),
        "stub_hex": stub.hex(), "stub_sha256": sha256(stub),
        "stub_rows": [view.row(ins) for ins in decoded],
        "literal_name": "Ebl", "literal_rva": hex(STUB_RVA + 64),
        "main_fv_guid_rva": hex(MAIN_GUID_RVA), "main_fv_guid": MAIN_GUID,
        "original_abl_fv_guid_rva": hex(ABL_GUID_RVA), "original_abl_fv_guid": ABL_GUID,
        "proposed_pe_buffer_sha256": sha256(patched_memory),
        "static_direct_branch_refs_into_padding": refs, "aligned_qword_refs_into_padding": pointers,
        "padding_globally_proven_unused": False,
        "flow": ["Existing charger application and PIL ABL preparation remain before the hook",
                 "Launch Ebl in Main FV using the native BDS helper",
                 "If Ebl returns, restore original arguments and launch LinuxLoader in ABL FV",
                 "Return LinuxLoader status to original continuation RVA 0x5258"],
        "authentication_limit": "Modifying QcomBds requires an accepted UEFI modification or pre-existing runtime write path; neither is established",
        "abl_modified_by_this_hook": False, "firmware_image_emitted": False,
        "runtime_uefi_or_authentication_tested": False, "hardware_writes_or_reboots": False,
    }


def main_fv_apps(uefi):
    matches = []
    for origin, blob in expanded_blobs(uefi):
        if origin != "raw/lzma@0x4e268":
            continue
        require(blob[0x68:0x78] == uuid.UUID(MAIN_GUID).bytes_le, "Main FV header identity differs")
        for file, name, guid in named_firmware_files(blob):
            if name in {"Ebl", "QcomChargerApp"}:
                payloads = pe_images(file.data)
                matches.append({"name": name, "ffs_guid": guid, "ffs_type": file.type,
                                "pe_sha256": sha256(payloads[0].data), "origin": origin,
                                "fv_expanded_buffer_offset": "0x8"})
    require({x["name"] for x in matches} == {"Ebl", "QcomChargerApp"},
            "Required native applications not found in Main FV")
    return matches


def emulate(stub=None):
    """Execute real ARM64 hook bytes, with a mocked BDS launch function only."""
    import unicorn
    from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
    from unicorn import arm64_const as regs
    stub = build_stub() if stub is None else stub
    rows = []
    for base in [0x10000000, 0xB7000000]:
        for ebl_status in [0, 0x800000000000000E]:
            for linux_status in [0, 0x8000000000000001]:
                machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                machine.mem_map(base, 0x20000)
                stack = 0x40000000
                machine.mem_map(stack, 0x20000)
                sp = stack + 0x10000
                machine.mem_write(base + CALL_RVA, encode_bl(CALL_RVA, STUB_RVA))
                machine.mem_write(base + STUB_RVA, stub)
                machine.mem_write(base + LAUNCH_RVA, bytes.fromhex("c0035fd6"))
                for rva, guid in [(MAIN_GUID_RVA, MAIN_GUID), (ABL_GUID_RVA, ABL_GUID)]:
                    machine.mem_write(base + rva, uuid.UUID(guid).bytes_le)
                name_ptr = sp + 0x80
                machine.mem_write(name_ptr, "LinuxLoader\0".encode("utf-16le"))
                preserved = {}
                for number in range(19, 30):
                    register = getattr(regs, "UC_ARM64_REG_X" + str(number))
                    preserved[register] = 0xA0000000 + number
                    machine.reg_write(register, preserved[register])
                machine.reg_write(regs.UC_ARM64_REG_X0, base + ABL_GUID_RVA)
                machine.reg_write(regs.UC_ARM64_REG_X1, name_ptr)
                machine.reg_write(regs.UC_ARM64_REG_X2, 0)
                machine.reg_write(regs.UC_ARM64_REG_SP, sp)
                calls = []

                def launch(uc, address, size, user_data):
                    if address != base + LAUNCH_RVA:
                        return
                    pointer = uc.reg_read(regs.UC_ARM64_REG_X1)
                    name = bytearray()
                    for i in range(64):
                        pair = bytes(uc.mem_read(pointer + i * 2, 2))
                        if pair == b"\0\0":
                            break
                        name.extend(pair)
                    calls.append({"fv_guid": str(uuid.UUID(bytes_le=bytes(uc.mem_read(
                        uc.reg_read(regs.UC_ARM64_REG_X0), 16)))),
                        "name": name.decode("utf-16le"), "arg2": uc.reg_read(regs.UC_ARM64_REG_X2),
                        "sp_aligned_16": uc.reg_read(regs.UC_ARM64_REG_SP) % 16 == 0})
                    require(len(calls) <= 2, "Unexpected extra BDS launch")
                    # A real called function may destroy all caller-saved X0..X18/NZCV.
                    for number in range(1, 19):
                        uc.reg_write(getattr(regs, "UC_ARM64_REG_X" + str(number)), 0xDEAD0000 + number)
                    uc.reg_write(regs.UC_ARM64_REG_NZCV, 0xF0000000)
                    uc.reg_write(regs.UC_ARM64_REG_X0, ebl_status if len(calls) == 1 else linux_status)

                machine.hook_add(UC_HOOK_CODE, launch)
                machine.emu_start(base + CALL_RVA, base + CALL_RVA + 4, timeout=100000, count=200)
                require([(x["fv_guid"], x["name"], x["arg2"]) for x in calls] == [
                    (MAIN_GUID, "Ebl", 0), (ABL_GUID, "LinuxLoader", 0)], "Wrong launch order/namespace/arguments")
                require(all(x["sp_aligned_16"] for x in calls) and
                        machine.reg_read(regs.UC_ARM64_REG_SP) == sp, "Stack alignment or restoration failed")
                require(all(machine.reg_read(reg) == value for reg, value in preserved.items()),
                        "Callee-saved register changed")
                require(machine.reg_read(regs.UC_ARM64_REG_PC) == base + CALL_RVA + 4 and
                        machine.reg_read(regs.UC_ARM64_REG_X0) == linux_status,
                        "Continuation or LinuxLoader return status differs")
                rows.append({"image_base": hex(base), "ebl_status": hex(ebl_status),
                             "linuxloader_status": hex(linux_status), "calls": calls,
                             "stack_and_callee_saved_registers_restored": True,
                             "original_continuation_reached": True})
    return {"engine": "Unicorn", "version": unicorn.__version__, "cases": rows,
            "bds_helper_mocked": True, "uefi_firmware_executed": False,
            "interpretation": "ARM64 control-flow/ABI test only, not EFI execution or authentication"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--out", type=Path, default=Path("generated/ebl-first"))
    parser.add_argument("--emulate", action="store_true")
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        uefi = read_member(archive, "cn/uefi.elf")
    require(sha256(uefi) == UEFI_SHA256, "Unknown CN UEFI container hash")
    data = next(p.data for p in pe_images(uefi) if sha256(p.data) == QCOMBDS_SHA256)
    report = plan_for_pe(data)
    report["main_fv_applications"] = main_fv_apps(uefi)
    if args.emulate:
        report["arm64_emulation"] = emulate()
    write_json(args.out / "hook-plan.json", report)
    (args.out / "ebl_first_stub.bin").write_bytes(build_stub())
    assembly = ["// Disassembly listing for review; use plan_ebl_first.py to generate authoritative bytes.",
                "// New hook program only; placement is QcomBds RVA 0x1C900.",
                "// Calls are to existing helper RVA 0x7D2C. This is not a complete EFI image."]
    assembly += [f'// {row["rva"]} {row["bytes"]}\n  {row["mnemonic"]} {row["operands"]}'.rstrip()
                 for row in report["stub_rows"]]
    assembly += ['// RVA 0x1C940: UTF-16LE "Ebl\\0"', '.byte 0x45,0,0x62,0,0x6c,0,0,0']
    (args.out / "ebl_first.S").write_text("\n".join(assembly) + "\n")
    print("PASS: generated Ebl-first hook study" + ("; eight ARM64 ABI cases passed" if args.emulate else ""))
    print("NOT TESTED: UEFI execution, authentication, actual padding ownership or custom EFI boot")


if __name__ == "__main__":
    main()
