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

from fwlib import largest_pe, named_firmware_files, pe_images, read_member, sha256
from map_bootstate import analyze_image
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
    parser.add_argument("--live-archive", type=Path, help="Optional private live-boot capture ZIP")
    parser.add_argument("--logo-archive", type=Path, help="Optional user-provided MediaTek comparison ZIP")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    results = []
    with tempfile.TemporaryDirectory(prefix="sm8750-research-") as temporary:
        generated = Path(temporary) / "evidence"
        for script, options in [
            ("analyze.py", ["--out", str(generated)]),
            ("trace_paths.py", ["--upstream", str(args.upstream),
                                "--out", str(generated / "continued")]),
            ("map_bootstate.py", ["--out", str(generated / "bootstate")]),
            ("trace_diagnostics.py", ["--out", str(generated / "bootstate")]),
            ("trace_ebl_entry.py", ["--out", str(generated / "entry")]),
            ("plan_ebl_first.py", ["--out", str(generated / "ebl-first"), "--emulate"]),
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
        annibale = project / "annibale"
        stock_elf = annibale / "src/OS3.0.307.0.WPKCNXM_abl.elf"
        candidate_elf = annibale / "OS3.0.307.0.WPKCNXM_abl.elf"
        with zipfile.ZipFile(args.archive) as archive:
            require(stock_elf.read_bytes() == read_member(archive, "cn/abl.elf"),
                    "Bundled annibale default differs from original ZIP member")
        for script in ("patch.py", "verify_signature.py", "patch_uefi_ebl_first.py", "verify_uefi_signature.py"):
            run = subprocess.run([sys.executable, str(annibale / "src" / script), "--check"],
                                 text=True, capture_output=True, timeout=120)
            require(run.returncode == 0, "Annibale " + script + " failed:\n" + run.stdout + run.stderr)
        repacked_pe = largest_pe(candidate_elf.read_bytes()).data
        require(repacked_pe != cn,
                "Repacked ELF still contains stock LinuxLoader")
        require(sha256(repacked_pe) ==
                "9b55fb1ee70b3519a947160033d4d9929edf6d045d6dbc0c4e39b23fdf8fffc5",
                "Independent PE extraction differs from the previous CN candidate")
        results.append("PASS: annibale stock equals ZIP; rebuilt ELF/report reproduce exactly; independent extraction matches CN candidate")
        results.append("PASS: OEM stock ECDSA signature valid; research candidate invalid despite valid segment digests (not boot-ready)")
        stock_uefi = annibale / "src/OS3.0.307.0.WPKCNXM_uefi.elf"
        candidate_uefi = annibale / "OS3.0.307.0.WPKCNXM_uefi_EBL_FIRST_RESEARCH.elf"
        with zipfile.ZipFile(args.archive) as archive:
            require(stock_uefi.read_bytes() == read_member(archive, "cn/uefi.elf"),
                    "Bundled UEFI default differs from original ZIP")
        before = {sha256(p.data): p.data for p in pe_images(stock_uefi.read_bytes())}
        after = {sha256(p.data): p.data for p in pe_images(candidate_uefi.read_bytes())}
        require(len(before) == len(after) == 104 and
                before.keys() - after.keys() == {
                    "c15c9077837d13420a860a20a6480d9dd8ae76f31828890a598f38be47d2bd78"} and
                after.keys() - before.keys() == {
                    "6a2ae633b79c979dfffad7df8100c5c624fc52c5cc71601a16139f635a7da16e"},
                "UEFI module inventory changed beyond the single planned QcomBds PE")
        require(all(before[k] == after[k] for k in before.keys() & after.keys()),
                "An unrelated UEFI PE changed")
        require(any(g == "d14c51ed-4f4d-2f2d-eae4-77914692d046"
                    for f, n, g in named_firmware_files(candidate_uefi.read_bytes())),
                "Independent FV parser cannot reach the original following FFS")
        hooked_pe = after["6a2ae633b79c979dfffad7df8100c5c624fc52c5cc71601a16139f635a7da16e"]
        require(hooked_pe[0x1C900:0x1C948] ==
                (project / "annibale/research/ebl_first_stub.bin").read_bytes() and
                hooked_pe[0x5254:0x5258] == bytes.fromhex("ab5d0094"),
                "Actual container does not contain the planned Ebl-first code")
        results.append("PASS: Ebl-first UEFI ELF/report reproduce exactly; default equals ZIP; 104 independent PE extractions show only QcomBds changed and 103 unchanged")
        results.append("PASS: independent FV parser reaches following original FFS through new PAD; extracted QcomBds contains exact 72-byte stub/call")
        results.append("PASS: UEFI stock ECDSA signature VALID, modified signature INVALID; original certificates/signature/trailing bytes preserved")
        maps = {tag: json.loads((generated / f"bootstate/{tag}_bootstate_map.json").read_text())
                for tag in ("cn", "eng")}
        for tag, report in maps.items():
            require(report["counts"] == {
                "upstream_mask_hits": 0, "structural_bootstate_hits": 1,
                "source_template_hits": 1, "local_sink_hits": 1,
                "device_state_string_dispatch_hits": 1}, "Ambiguous or changed structural anchors")
            require(len(report["candidate_edits"]) == 4 and
                    report["changed_byte_count"] == (10 if tag == "cn" else 9),
                    "Unexpected candidate edit count")
            require(not report["candidate_container_created"], "Unexpected firmware output")
        require(maps["eng"]["byte_identical_to_supplied_result"], "Engineering calibration missing")
        require(maps["cn"]["source"]["getter_rva"] == "0x24874" and
                maps["cn"]["bootstate"]["test_rva"] == "0x3b76c" and
                maps["cn"]["candidate_pe_sha256"] ==
                "9b55fb1ee70b3519a947160033d4d9929edf6d045d6dbc0c4e39b23fdf8fffc5",
                "Documented CN candidate changed")
        results.append("PASS: unique structural anchors in CN/ENG; engineering calibration is byte-identical")
        for name, original in (("CN", cn), ("engineering", eng)):
            mutation = original[:100] + bytes([original[100] ^ 1]) + original[101:]
            try:
                analyze_image(mutation)
            except ValueError as error:
                require("Unknown PE hash" in str(error), "Mutation failed for an unexpected reason")
            else:
                raise RuntimeError("Structural analyzer accepted altered " + name)
        results.append("PASS: structural analyzer refuses one-byte mutations of both identified builds")
        diagnostics = json.loads((generated / "bootstate/cn_oem_diagnostics.json").read_text())
        require(diagnostics["registration"]["entry_count"] == 34 and
                diagnostics["registration"]["selected_entries"]["oem uefilog"]["handler_rva"] ==
                "0x82abc" and diagnostics["uefilog_argument_branch"]["argument_marker"] == "save",
                "CN diagnostic dispatch or argument branch changed")
        results.append("PASS: 34-entry CN command table and diagnostic save branch match input bytes")
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
        entry = json.loads((generated / "entry/bds_entry.json").read_text())
        ebl = json.loads((generated / "entry/ebl_ram_fv.json").read_text())
        require(entry["callbacks"][4]["target_rva"] == "0x59dc" and
                entry["default_call"]["file_offset"] == "0x1dec" and
                ebl["process_firmware_volume_field"] == "0x98" and
                ebl["registrations"][0]["name"] == "loadfv" and
                not ebl["custom_efi_entry_tested"] and not ebl["hardware_writes_or_reboots"],
                "Ebl bridge evidence or execution boundaries differ")
        pil = json.loads((generated / "entry/pil_binding.json").read_text())
        require(pil["interface_method_0x08_target_rva"] == "0x1790" and
                pil["consumer_argument"] == "ABL" and not pil["ebl_entry_established"],
                "PIL protocol producer/consumer binding differs")
        results.append("PASS: early platform callback table and native Ebl RAM/file routes match pinned PEs")
        hook = json.loads((generated / "ebl-first/hook-plan.json").read_text())
        require(hook["call_rva"] == "0x5254" and hook["stub_size"] == 72 and
                len(hook["arm64_emulation"]["cases"]) == 8 and
                not hook["firmware_image_emitted"] and not hook["runtime_uefi_or_authentication_tested"],
                "Ebl-first hook study or execution boundaries differ")
        require((generated / "ebl-first/ebl_first_stub.bin").read_bytes() ==
                (project / "annibale/research/ebl_first_stub.bin").read_bytes(),
                "Published hook program bytes differ from the generator")
        results.append("PASS: 72-byte Ebl-first hook, Main FV inventory and eight emulated ARM64 ABI/status cases")
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
        if args.live_archive:
            run = subprocess.run([sys.executable, str(project / "src/analyze_live_boot.py"),
                                  str(args.live_archive), "--firmware", str(args.archive),
                                  "--out", str(generated / "live")],
                                 text=True, capture_output=True, timeout=120)
            require(run.returncode == 0, "Live analysis failed:\n" + run.stdout + run.stderr)
            live = json.loads((generated / "live/summary.json").read_text())
            relationship = json.loads((generated / "live/entry_relationships.json").read_text())
            require(live["uefi_log_count"] == 5 and live["toolsfv_applications"] == 19 and
                    live["shell_and_ebl_present"] and relationship["namespaces_differ"],
                    "Live-capture evidence differs")
            require(not live["hardware_writes_or_reboots"] and not live["custom_efi_entry_tested"],
                    "Unexpected device execution claim")
            results.append("PASS: private live input hashes, FAT12 logs, Tools FV apps, and BDS namespace cross-check")
        if args.logo_archive:
            logo_out = generated / "logo-comparison"
            cert_out = generated / "abl-certificates"
            run = subprocess.run([sys.executable, str(project / "src/analyze_logo_donor.py"),
                                  str(args.logo_archive), "--firmware", str(args.archive),
                                  "--out", str(logo_out), "--cert-out", str(cert_out)],
                                 text=True, capture_output=True, timeout=120)
            require(run.returncode == 0, "Logo comparison failed:\n" + run.stdout + run.stderr)
            comparison = json.loads((logo_out / "comparison.json").read_text())
            require(comparison["logo1"]["override_prefix_size"] == 90 and
                    comparison["repacked_already_has_donor_certificate_payloads"] and
                    comparison["qualcomm"]["stock_abl_and_uefi_share_all_three_certificate_bytes"] and
                    comparison["qualcomm"]["packaged_candidate_already_preserves_abl_signature_and_certificates"],
                    "Logo/Qualcomm certificate comparison differs")
            for file in cert_out.iterdir():
                require(file.read_bytes() == (project / "annibale/research/certs" / file.name).read_bytes(),
                        "Exported ABL certificate/signature bytes differ")
            results.append("PASS: MediaTek 90-byte hash override/alignment, Qualcomm stock signatures and exact ABL certificate exports")
        for source in (project / "src").glob("*.py"):
            py_compile.compile(str(source), cfile=str(Path(temporary) / (source.stem + ".pyc")),
                               doraise=True)
        subprocess.run(["sh", "-n", str(project / "tools/collect_readonly.sh")], check=True)
        results.append("PASS: Python syntax and Android collector shell syntax")
    results.append("NOT TESTED: modified firmware execution, custom BDS entry, signature acceptance, or working fake lock")
    log = "\n".join(results) + "\n"
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text(log)
    print(log, end="")


if __name__ == "__main__":
    main()
