#!/usr/bin/env python3
"""Offline regression checks for patch recovery and documented boot evidence."""
import argparse
import json
import py_compile
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from fwlib import largest_pe, read_member
from recover_patch import reproduce
from trace_paths import audit_hash_segment


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    results = []
    with tempfile.TemporaryDirectory(prefix="sm8750-research-") as temporary:
        generated = Path(temporary) / "evidence"
        for script, options in [
            ("analyze.py", ["--out", str(generated)]),
            ("trace_paths.py", ["--upstream", str(args.upstream),
                                "--out", str(generated / "continued")]),
        ]:
            run = subprocess.run([sys.executable, str(project / "src" / script),
                                  str(args.archive), *options],
                                 text=True, capture_output=True, timeout=120)
            require(run.returncode == 0, script + " failed:\n" + run.stdout + run.stderr)
            results.append("PASS: " + script + " reproduces evidence from input bytes")
        with zipfile.ZipFile(args.archive) as archive:
            eng = largest_pe(read_member(archive, "eng rom/abl.elf")).data
            cn = largest_pe(read_member(archive, "cn/abl.elf")).data
            supplied = read_member(archive, "result/boot.efi")
            eng_container = read_member(archive, "eng rom/abl.elf")
        require(reproduce(eng) == supplied, "Recovered payload differs from supplied result")
        require(sum(a != b for a, b in zip(eng, supplied)) == 9,
                "Unexpected number of changed bytes")
        results.append("PASS: patch recovery is byte-identical; 9 changed bytes")
        for name, data in (("CN firmware", cn),
                           ("one-byte engineering mutation", eng[:100] +
                            bytes([eng[100] ^ 1]) + eng[101:])):
            try:
                reproduce(data)
            except ValueError:
                results.append("PASS: hash guard rejects " + name)
            else:
                raise RuntimeError("Hash guard accepted " + name)
        summary = json.loads((generated / "summary.json").read_text())
        require(summary["cn"]["unique_uefi_pe_images"] == 104 and
                summary["eng"]["unique_uefi_pe_images"] == 104,
                "Unexpected extracted module counts")
        require(summary["cn"]["qcombds_sha256"] == summary["eng"]["qcombds_sha256"],
                "QcomBds differs between input builds")
        results.append("PASS: both UEFI images have 104 unique PEs and identical QcomBds")
        trace = json.loads((generated / "continued/boot_container_trace.json").read_text())
        for tag in ("cn", "eng"):
            require(any(x["fv_name_guid"] == trace["dispatch"]["fv_argument_guid"]
                        for x in trace[tag]["firmware_volumes"]),
                    "Dispatch and actual ABL FV GUID differ")
            require(any(x["algorithm"] == "sha384" and
                        x["digest_file_offset"] == "0x51150"
                        for x in trace[tag]["container"]["digest_matches"]),
                    "Expected embedded payload SHA-384 not found")
            assembly = {int(line.split(":", 1)[0], 16):
                        line.split(":", 1)[1].split()
                        for line in (generated / f"{tag}_qcombds.disasm.txt").read_text().splitlines()}
            for address, destination in [(0x1FA8, 0x1D44), (0x1DEC, 0x4FF4),
                                         (0x510C, 0x4E90), (0x5254, 0x7D2C),
                                         (0x5258, 0x5684)]:
                require(assembly.get(address) == ["bl", f"#0x{destination:x}"],
                        "Documented direct-call edge differs")
        results.append("PASS: actual ABL FV GUID, embedded SHA-384, and call edges match for both builds")
        corrupted = bytearray(eng_container)
        corrupted[0x1100] ^= 1
        require(not audit_hash_segment(bytes(corrupted))["digest_matches"],
                "Changed payload unexpectedly matches the original hash segment")
        results.append("PASS: changing the ELF payload breaks the embedded digest match")
        protocols = json.loads((generated / "continued/protocol_inventory.json").read_text())
        require(len(protocols["protocols"]) == 33 and
                all(row["variants"] for row in protocols["protocols"]),
                "Protocol declarations unresolved or changed")
        results.append("PASS: 33 protocol declarations resolved from pinned source")
        for source in (project / "src").glob("*.py"):
            py_compile.compile(str(source), cfile=str(Path(temporary) / (source.stem + ".pyc")),
                               doraise=True)
        subprocess.run(["sh", "-n", str(project / "tools/collect_readonly.sh")], check=True)
        results.append("PASS: Python syntax and Android collector shell syntax")
    results.append("NOT TESTED: device execution, custom BDS entry, signature acceptance, or working fake lock")
    log = "\n".join(results) + "\n"
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text(log)
    print(log, end="")


if __name__ == "__main__":
    main()
