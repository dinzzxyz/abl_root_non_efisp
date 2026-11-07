#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the stock and research ELF signatures with the embedded leaf key.

This is an offline cryptographic check, not proof of the device's root of trust.
The expected research outcome is stock VALID and modified ELF INVALID.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import patch


def der_object(data, offset=0):
    patch.require(offset + 2 <= len(data) and data[offset] == 0x30, "Expected DER SEQUENCE")
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        patch.require(1 <= count <= 4 and start + count <= len(data), "Invalid DER length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + length
    patch.require(start <= end <= len(data), "Truncated DER object")
    return data[offset:end], end


def signature_result(image, *, layout=patch):
    layout.check_elf(image)
    signature_block = image[layout.SIGNATURE_START:layout.CERT_START]
    signature, end = der_object(signature_block)
    patch.require(signature_block[end:] == bytes(len(signature_block) - end),
                  "Unexpected ECDSA signature padding")
    chain = image[layout.CERT_START:getattr(layout, "CERT_END", len(image))]
    certificates, cursor, sizes = [], 0, []
    while cursor < len(chain) and chain[cursor] == 0x30:
        patch.require(len(certificates) < 8, "Too many certificates")
        encoded, next_cursor = der_object(chain, cursor)
        certificates.append(x509.load_der_x509_certificate(encoded))
        sizes.append(len(encoded))
        cursor = next_cursor
    patch.require(len(certificates) == 3 and chain[cursor:] == b"\xFF" * (len(chain) - cursor),
                  "Unexpected OEM certificate chain/padding")
    key = certificates[0].public_key()
    patch.require(isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp384r1",
                  "Expected OEM leaf P-384 public key")
    signed_data = image[layout.PAYLOAD_END:layout.SIGNATURE_START]
    try:
        key.verify(signature, signed_data, ec.ECDSA(hashes.SHA384()))
        valid = True
    except InvalidSignature:
        valid = False
    links = []
    for child, parent in [(0, 1), (1, 2), (2, 2)]:
        cert = certificates[child]
        parent_key = certificates[parent].public_key()
        patch.require(isinstance(parent_key, ec.EllipticCurvePublicKey), "Expected EC certificate key")
        try:
            parent_key.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
            link_valid = True
        except InvalidSignature:
            link_valid = False
        links.append({"certificate_index": child, "issuer_key_index": parent,
                      "cryptographic_signature_valid": link_valid})
    return {"elf_sha256": patch.sha256(image),
            "algorithm": "ECDSA secp384r1 with SHA-384",
            "signed_file_range_start": hex(layout.PAYLOAD_END),
            "signed_file_range_end_exclusive": hex(layout.SIGNATURE_START),
            "signed_size": len(signed_data), "signed_data_sha384": hashlib.sha384(signed_data).hexdigest(),
            "signature_file_offset": hex(layout.SIGNATURE_START),
            "signature_block_size": len(signature_block), "signature_der_size": len(signature),
            "signature_zero_padding_size": len(signature_block) - len(signature),
            "oem_image_signature_valid_with_embedded_leaf_key": valid,
            "certificate_file_offset": hex(layout.CERT_START), "certificate_sizes": sizes,
            "certificate_sha256": [c.fingerprint(hashes.SHA256()).hex() for c in certificates],
            "certificate_padding_ff_size": len(chain) - cursor, "certificate_signature_links": links,
            "elf_header_and_payload_hashes_valid": True}


def audit(stock, candidate, *, layout=patch):
    patch.require(patch.sha256(stock) == layout.STOCK_SHA256, "Unknown stock ELF hash")
    patch.require(patch.sha256(candidate) == layout.PATCHED_ELF_SHA256, "Unknown candidate ELF hash")
    original = signature_result(stock, layout=layout)
    modified = signature_result(candidate, layout=layout)
    patch.require(original["oem_image_signature_valid_with_embedded_leaf_key"],
                  "Original signature failed; cannot use this interpretation as a calibrated check")
    patch.require(not modified["oem_image_signature_valid_with_embedded_leaf_key"],
                  "Modified signature unexpectedly valid; investigate before publishing")
    return {"cryptography_version": cryptography.__version__, "stock": original,
            "candidate": modified, "expected_research_result_confirmed": True,
            "interpretation": "Original OEM signature validates; retained signature fails on the modified signed bytes",
            "device_fused_root_or_runtime_authentication_tested": False,
            "hardware_writes_or_reboots": False}


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", type=Path, default=root / "src" / patch.NAME)
    parser.add_argument("--candidate", type=Path, default=root / patch.NAME)
    parser.add_argument("--report", type=Path, default=root / "signature-audit.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    patch.require(len({p.resolve() for p in [args.stock, args.candidate, args.report]}) == 3,
                  "Stock, candidate and report must be different files")
    result = audit(args.stock.read_bytes(), args.candidate.read_bytes())
    content = (json.dumps(result, indent=2) + "\n").encode()
    if args.check:
        patch.require(args.report.read_bytes() == content, "Existing signature report differs")
    else:
        patch.atomic_write(args.report, content)
    print("Stock OEM image signature: VALID with embedded leaf public key")
    print("Patched OEM image signature: INVALID (expected; the candidate is not OEM-resigned)")
    print("Device root-of-trust policy and runtime image acceptance: NOT TESTED")


if __name__ == "__main__":
    main()
