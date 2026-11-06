#!/usr/bin/env python3
"""Record CN OEM diagnostic dispatch offline; do not execute OEM commands.

All instruction locations are specific to the exact CN PE hash below.
Handler presence is not proof of runtime availability or absence of side effects.
"""
import argparse
import struct
import uuid
import zipfile
from pathlib import Path

from fwlib import largest_pe, read_member, sha256, write_json
from map_bootstate import View, adrl, immediate, memory, reg, require

CN_PE_SHA256 = "75e9d6122d708948c6a5f0b9774a061aa25ebb7a279fbe020ad8835400b065d2"


def analyze(data):
    require(sha256(data) == CN_PE_SHA256, "Diagnostic trace only applies to the identified CN PE")
    view = View(data)

    # Decode the registration loop's base, limit, LDP displacement, and stride.
    base, _ = adrl(view, 0x7E24C)
    cmp = view.instructions(0x7E254, 4)[0]
    load = view.instructions(0x7E260, 4)[0]
    step = view.instructions(0x7E268, 4)[0]
    require(cmp.mnemonic == "cmp" and reg(cmp, 0) == "x19", "Loop limit differs")
    require(load.mnemonic == "ldp" and reg(load, 0) == "x0" and reg(load, 1) == "x1",
            "Command/handler pair load differs")
    require(step.mnemonic == "add" and reg(step, 0) == reg(step, 1) == "x19",
            "Loop stride differs")
    stride, limit = immediate(step, 2), immediate(cmp, 1)
    require(stride == 16 and limit == 0x220, "Unexpected registration bounds")
    table_rva = base + memory(load, 2)[1]
    table = []
    for index in range(limit // stride):
        entry_rva = table_rva + index * stride
        command, handler = struct.unpack_from("<QQ", data, view.offset(entry_rva))
        name = view.cstring(command)
        require(name is not None and view.executable(view.offset(handler)), "Malformed dispatch entry")
        table.append({"entry_rva": hex(entry_rva), "entry_file_offset": hex(view.offset(entry_rva)),
                      "command": name, "string_rva": hex(command), "handler_rva": hex(handler),
                      "entry_bytes": data[view.offset(entry_rva):view.offset(entry_rva) + 16].hex()})
    selected = {r["command"]: r for r in table if r["command"] in
                ("oem lkmsg", "oem lpmsg", "oem uefilog")}
    require(len(selected) == 3, "Diagnostic entries missing")
    handlers = {}
    for name, entry in selected.items():
        index = table.index(entry)
        start = view.offset(int(entry["handler_rva"], 16))
        end = view.offset(int(table[index + 1]["handler_rva"], 16))
        require(0 < end - start <= 0x400, "Unexpected selected handler size")
        handlers[name] = {**entry, "instructions": view.rows(start, end - start)}

    # LocateProtocol: ADRP X0 ... ADD X0,X0,#imm; BLR via BootServices +0x140.
    page = view.instructions(0x82AD4, 4)[0]
    add = view.instructions(0x82AF8, 4)[0]
    guid_rva = immediate(page, 1) + immediate(add, 2)
    guid_bytes = data[view.offset(guid_rva):view.offset(guid_rva) + 16]
    save_string, _ = adrl(view, 0x82B08)
    failure_string, _ = adrl(view, 0x82C64)
    require(view.cstring(save_string) == "save", "Save argument marker differs")
    require("save logfs files failed" in view.cstring(failure_string), "Save diagnostic differs")
    branch = view.instructions(0x82B14, 4)[0]
    require(branch.mnemonic == "cbz" and immediate(branch, 1) == 0x82BB8,
            "Save branch target differs")
    return {
        "input_pe_sha256": sha256(data), "image_base": "0x0", "hardware_execution": False,
        "registration": {"loop": view.rows(0x7E248, 0x28), "table_rva": hex(table_rva),
                         "entry_count": len(table), "entry_stride_bytes": stride,
                         "register_call_rva": "0x7e264", "register_helper_rva": "0x7e6c0",
                         "selected_entries": selected},
        "handlers": handlers,
        "logfs_protocol_reference": {"guid_rva": hex(guid_rva), "guid_bytes": guid_bytes.hex(),
                                     "guid": str(uuid.UUID(bytes_le=guid_bytes)),
                                     "locate_sequence": view.rows(0x82AD4, 0x2C),
                                     "provider_or_runtime_installation_proven": False},
        "uefilog_argument_branch": {
            "argument_marker": "save", "argument_marker_rva": hex(save_string),
            "compare_and_branch": view.rows(0x82B04, 0x14),
            "comparison_helper": view.rows(0x86278, 8),
            "save_method_sequence": view.rows(0x82BB8, 16),
            "other_method_sequence": view.rows(0x82B34, 0x2C),
            "save_failure_message": view.cstring(failure_string),
            "save_failure_marker": view.rows(0x82C64, 0x18),
            "interpretation": "save selects a different protocol method; may persist log files",
        },
        "minidump_helpers": {"load_fragment": view.rows(0x85FB0, 24),
                             "data_fragment": view.rows(0x8611C, 16)},
        "limitations": ["Commands are present in the static registration table, not tested on USB",
                        "No assertion that the handlers or all called methods are read-only",
                        "No OEM command was executed or prescribed by this tool",
                        "Protocol GUID occurrence alone does not identify its provider",
                        "These are diagnostic paths, not an EFI launch entry"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        data = largest_pe(read_member(archive, "cn/abl.elf")).data
    report = analyze(data)
    write_json(args.out / "cn_oem_diagnostics.json", report)
    lines = ["CN LinuxLoader diagnostic paths; static evidence, no OEM commands executed"]
    for name, section in [("registration loop", report["registration"]["loop"]),
                          *[(name, handler["instructions"]) for name, handler in report["handlers"].items()],
                          ("argument comparison helper", report["uefilog_argument_branch"]["comparison_helper"])]:
        lines.append("\n" + name)
        for row in section:
            lines.append((f"file {row['file_offset']:>9} / RVA {row['rva']:>9}: "
                          f"{row['bytes']:<16} {row['mnemonic']:<7} {row['operands']}").rstrip())
    (args.out / "cn_oem_diagnostics_trace.txt").write_text("\n".join(lines) + "\n")
    print("PASS: CN table has 34 entries; lkmsg/lpmsg/uefilog handlers mapped")
    print("NOTE: uefilog has a save-argument branch; command side effects not fully audited")


if __name__ == "__main__":
    main()
