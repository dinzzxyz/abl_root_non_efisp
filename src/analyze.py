#!/usr/bin/env python3
"""Reproduce the archive-only SM8750 SuperFastboot path investigation."""
import argparse
import io
import json
import re
import zipfile
from pathlib import Path

import capstone
import pefile

from fwlib import (fdt_properties, largest_pe, named_firmware_files, pe_images,
                   read_member, sha256, write_json)
from recover_patch import EDITS, reproduce


def disassembly(data: bytes, ranges: list[tuple[int, int]]) -> str:
    pe = pefile.PE(data=data, fast_load=True)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    lines = []
    for section in pe.sections:
        if section.Characteristics & 0x20000000:
            address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            for ins in md.disasm(section.get_data(), address):
                if any(lo <= ins.address < hi for lo, hi in ranges):
                    lines.append(f"{ins.address:08x}: {ins.mnemonic:8} {ins.op_str}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    summary = {"archive_sha256": sha256(args.archive.read_bytes()), "inputs": {}}
    with zipfile.ZipFile(args.archive) as archive:
        inventory = [{"name": i.filename, "size_bytes": i.file_size}
                     for i in archive.infolist()]
        write_json(args.out / "archive_inventory.json", inventory)
        supplied = read_member(archive, "result/boot.efi")
        eng_image = largest_pe(read_member(archive, "eng rom/abl.elf"))
        recovered = reproduce(eng_image.data)
        if recovered != supplied:
            raise ValueError("Recovery differs from supplied result")
        summary["patch_recovery"] = {
            "identical_to_supplied": True, "original_sha256": sha256(eng_image.data),
            "result_sha256": sha256(recovered),
            "changed_bytes": sum(a != b for a, b in zip(eng_image.data, recovered)),
            "ranges": [{"file_offset": hex(o), "before": a, "after": b}
                       for o, a, b in EDITS],
        }
        for tag, prefix in (("cn", "cn"), ("eng", "eng rom")):
            tagdata = {}
            for kind in ("abl", "uefi", "xbl_config"):
                name = f"{prefix}/{kind}.elf"
                raw = read_member(archive, name)
                summary["inputs"][name] = {
                    "size_bytes": len(raw), "sha256": sha256(raw),
                    "magic_hex": raw[:16].hex(),
                }
                if kind == "abl":
                    image = largest_pe(raw)
                    tagdata["abl"] = image.metadata()
                    if tag == "eng":
                        # These locations have been identified only for the
                        # hash-guarded engineering image used for recovery.
                        windows = [(off - 16, off + len(bytes.fromhex(before)) + 20)
                                   for off, before, _ in EDITS]
                        (args.out / "eng_abl_patch.disasm.txt").write_text(
                            disassembly(image.data, windows))
                        (args.out / "recovered_abl_patch.disasm.txt").write_text(
                            disassembly(recovered, windows))
                elif kind == "xbl_config":
                    props = fdt_properties(raw)
                    wanted = [p for p in props if p["path"].startswith("/sw/uefi")
                              or p["path"] == "/soc/pil/pil_images/ABL_CFG"]
                    write_json(args.out / f"{tag}_xbl_config_selected.json", wanted)
                    tagdata["fdt_property_count"] = len(props)
                else:
                    images = pe_images(raw)
                    tagdata["unique_uefi_pe_images"] = len(images)
                    names = {}
                    configs = {}
                    bds = None
                    for ff, name, guid in named_firmware_files(raw):
                        for section in ff.sections:
                            if section.type == 0x10:
                                digest = sha256(section.data)
                                names[digest] = {"name": name, "ffs_guid": guid,
                                                 "sha256": digest,
                                                 "size_bytes": len(section.data)}
                                if name == "QcomBds":
                                    bds = section.data
                                if name == "PILDxe":
                                    (args.out / f"{tag}_pildxe_validation.disasm.txt").write_text(
                                        disassembly(section.data, [
                                            (0x2364, 0x2400), (0x246C, 0x24A0),
                                            (0x2590, 0x25A0), (0x2898, 0x28C4),
                                            (0x3C24, 0x3C90)]))
                            if section.type == 0x19 and name in (
                                    "uefiplat.cfg", "uefipil.cfg", "BDS_Menu.cfg"):
                                configs[name] = section.data
                    write_json(args.out / f"{tag}_uefi_modules.json", list(names.values()))
                    for name, value in configs.items():
                        (args.out / f"{tag}_{name}").write_bytes(value)
                    if bds:
                        (args.out / f"{tag}_qcombds.disasm.txt").write_text(disassembly(bds, [
                            (0x1D44, 0x1E08), (0x1FA4, 0x1FB0),
                            (0x2000, 0x21F8), (0x2214, 0x2274),
                            (0x2620, 0x2640), (0x4E90, 0x4FF4),
                            (0x4FF4, 0x5150), (0x5200, 0x525C),
                            (0x7D2C, 0x7ED4), (0xEF18, 0xEF3C),
                            (0xEFFC, 0xF048)]))
                        tagdata["qcombds_sha256"] = sha256(bds)
                        # This data location is established only for the supplied build.
                        if sha256(bds) == "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78":
                            tagdata["qcombds_abl_fv_guid"] = str(__import__("uuid").UUID(
                                bytes_le=bds[0x1D0E8:0x1D0F8]))
            summary[tag] = tagdata
        module_bytes = read_member(archive, "magisk_module.zip")
        with zipfile.ZipFile(io.BytesIO(module_bytes)) as module:
            summary["reference_abl"] = {}
            for device in ("myron", "myron_global", "nezha_global"):
                raw = read_member(module, f"ablrepo/{device}/abl.img")
                image = largest_pe(raw)
                summary["reference_abl"][device] = image.metadata()
            summary["reference_bds"] = largest_pe(read_member(module, "BDS.efi")).metadata()
            # Evidence only: never execute any module script.
            for name in ("customize.sh", "bin/bl_flasher.sh", "efisp/BOOTENTRIES"):
                text = read_member(module, name).decode("utf-8")
                lines = [f"{i}: {line}" for i, line in enumerate(text.splitlines(), 1)
                         if re.search(r"efisp|persist|boot\.efi|BDS\.efi|LinuxLoader", line)]
                (args.out / ("reference_" + name.replace("/", "_") + ".txt")).write_text(
                    "\n".join(lines) + "\n")
    write_json(args.out / "summary.json", summary)
    print(json.dumps({
        "patch_reconstructed_exactly": summary["patch_recovery"]["identical_to_supplied"],
        "changed_bytes": summary["patch_recovery"]["changed_bytes"],
        "cn_uefi_unique_pe": summary["cn"]["unique_uefi_pe_images"],
        "eng_uefi_unique_pe": summary["eng"]["unique_uefi_pe_images"],
        "same_qcombds": summary["cn"]["qcombds_sha256"] == summary["eng"]["qcombds_sha256"],
        "output": str(args.out),
    }, indent=2))


if __name__ == "__main__":
    main()
