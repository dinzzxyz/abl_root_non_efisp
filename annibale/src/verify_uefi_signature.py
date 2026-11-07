#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the stock and experimental UEFI signatures, without device access."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import patch as support
import patch_uefi_ebl_first as uefi
from verify_signature import audit


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", type=Path, default=root / "src" / uefi.STOCK_NAME)
    parser.add_argument("--candidate", type=Path, default=root / uefi.NAME)
    parser.add_argument("--report", type=Path, default=root / "uefi-ebl-first-signature-audit.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    support.require(len({p.resolve() for p in [args.stock, args.candidate, args.report]}) == 3,
                    "Stock, candidate and report must be different files")
    stock, candidate = args.stock.read_bytes(), args.candidate.read_bytes()
    report = audit(stock, candidate, layout=uefi)
    report["target_component"] = "UEFI / QcomBds, NOT ABL"
    report["original_signature_certificate_chain_and_trailing_bytes_identical"] = (
        stock[uefi.SIGNATURE_START:] == candidate[uefi.SIGNATURE_START:])
    support.require(report["original_signature_certificate_chain_and_trailing_bytes_identical"],
                    "OEM signature/certificate region was modified")
    report["preserved_hash_segment_trailing_ff_bytes"] = len(stock) - uefi.CERT_END
    content = (json.dumps(report, indent=2) + "\n").encode()
    if args.check:
        support.require(args.report.read_bytes() == content, "Existing UEFI signature report differs")
    else:
        support.require(not args.report.exists() or args.report.read_bytes() == content,
                        "Refusing to overwrite a different existing signature report")
        support.atomic_write(args.report, content)
    print("Stock UEFI OEM image signature: VALID with embedded leaf public key")
    print("Ebl-first UEFI OEM image signature: INVALID despite valid segment digests")
    print("Original signature/certificates and 676 trailing FF bytes: PRESERVED")
    print("Runtime authentication, EFI execution and device boot: NOT TESTED")


if __name__ == "__main__":
    main()
