#!/usr/bin/env python3
"""Reproduce only the already-supplied EFI payload, with exact hash guards.

This does not build an ABL partition image or implement SuperFastboot.
It never opens block devices or calls adb, fastboot, su, or a flasher.
"""
import argparse
import zipfile
from pathlib import Path

from fwlib import largest_pe, read_member, sha256

ENGINEERING_ABL_SHA256 = "e0182863905a313c09d386c71d99dc23f469716ffa7ac58e9024ee106b37c70d"
ORIGINAL_EFI_SHA256 = "6270557b012660bd4d876a68368321d17a08efdb2e5a7d931a9f99346da736c7"
PATCHED_EFI_SHA256 = "d7456c0e5d6d102cad963ea9c27f4b5fc3c999d6ebce5ade058efd52c352ef83"

# File offsets in the extracted engineering LinuxLoader, not offsets in ELF.
EDITS = [
    (0x3A72C, "62a7ff97", "20008052"),
    (0x3BAAC, "28008052", "08008052"),
    (0x3BAEC, "ea030139", "ff030139"),
    (0x46BE8, "e90200b0298d2a91", "690200b029190e91"),
]


def reproduce(original: bytes) -> bytes:
    if sha256(original) != ORIGINAL_EFI_SHA256:
        raise ValueError("Engineering EFI hash mismatch; offsets do not apply")
    output = bytearray(original)
    for offset, before, after in EDITS:
        before, after = bytes.fromhex(before), bytes.fromhex(after)
        if output[offset:offset + len(before)] != before:
            raise ValueError(f"Original instructions differ at 0x{offset:x}")
        output[offset:offset + len(after)] = after
    if sha256(output) != PATCHED_EFI_SHA256:
        raise ValueError("Reconstructed result hash mismatch")
    return bytes(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive", type=Path, help="The original supplied gpt.zip")
    p.add_argument("--output", type=Path, help="Optional local EFI payload copy")
    args = p.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        abl = read_member(archive, "eng rom/abl.elf")
        supplied = read_member(archive, "result/boot.efi")
    if sha256(abl) != ENGINEERING_ABL_SHA256:
        raise ValueError("Input engineering ABL is a different build")
    original = largest_pe(abl).data
    recovered = reproduce(original)
    if recovered != supplied:
        raise ValueError("Reconstructed bytes differ from supplied result")
    changed = sum(x != y for x, y in zip(original, recovered))
    print(f"PASS: exact reconstruction; {changed} changed bytes / {len(EDITS)} ranges")
    print(f"SHA256: {sha256(recovered)}")
    print("Type: raw ARM64 EFI payload; not an ABL partition image")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Refuse overwriting an existing path, including an existing device node.
        with args.output.open("xb") as f:
            f.write(recovered)
        print(f"Local output: {args.output}")


if __name__ == "__main__":
    main()
