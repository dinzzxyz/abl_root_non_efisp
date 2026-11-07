#!/usr/bin/env python3
"""Read the supplied MediaTek logo example and compare Qualcomm authentication.

No uploaded script is executed and no logo or firmware image is rebuilt.
Optional outputs are public ABL certificates/signature bytes requested by user.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from fwlib import read_member, sha256, write_json

LOGO_ZIP_SHA256 = "549ddd66d6719553e2cfa035f0cecb68bef376a60c7eda0b4c988085066d0267"
MAGIC, EXT_MAGIC = bytes.fromhex("88168858"), bytes.fromhex("89168958")
NAMES = {b"logo1", b"logo2", b"cert1", b"cert2"}
MEMBERS = {
    "stock/logo.img": "801e1dc036c17b7cc2ecba1e71453f8eb8592df3e225f5ec059520ab29895117",
    "mod/logo_dash-repack.bin": "ce4865b6132958aeabad988c7eded90ed0a9ce565899d127af41c0f42907cdd7",
    "mod-signed/logo_dash-repack-signed.bin": "cb0ca9dc1cfa07193219682db6af0eed8fdbcd5afcff63ba592492e8f6f6c7f7",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tlv(data, offset=0):
    require(0 <= offset <= len(data) - 2, "Truncated ASN.1 item")
    tag, length, start = data[offset], data[offset + 1], offset + 2
    if length & 0x80:
        count = length & 0x7F
        require(1 <= count <= 4 and start + count <= len(data), "Invalid ASN.1 length")
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    end = start + length
    require(end <= len(data), "ASN.1 length exceeds buffer")
    return tag, data[start:end], end


def read_override(prefix):
    tag, body, end = tlv(prefix)
    require(tag == 0xA0 and end == len(prefix), "Expected one complete context-[0] block")
    items, cursor = [], 0
    while cursor < len(body):
        tag, value, cursor = tlv(body, cursor)
        items.append((tag, value))
    require([x[0] for x in items] == [6, 3, 6, 3], "Override does not contain OID/hash pairs")
    require(items[0][1] == bytes.fromhex("60867693160204") and
            items[2][1] == bytes.fromhex("60867693160201"), "Unexpected MediaTek hash OIDs")
    require(all(len(items[i][1]) == 33 and items[i][1][0] == 0 for i in [1, 3]),
            "Expected byte-aligned SHA-256 BIT STRINGs")
    return {"header_sha256": items[1][1][1:].hex(), "image_sha256": items[3][1][1:].hex()}


def scan_partitions(data):
    """Scan bounded headers to observe malformed alignment without repairing it."""
    result = []
    for found in re.finditer(re.escape(MAGIC), data):
        offset = found.start()
        if offset + 512 > len(data):
            continue
        name = data[offset + 8:offset + 40].split(b"\0")[0]
        if name not in NAMES or data[offset + 48:offset + 52] != EXT_MAGIC:
            continue
        size = struct.unpack_from("<I", data, offset + 4)[0]
        high = struct.unpack_from("<I", data, offset + 72)[0]
        header_size = struct.unpack_from("<I", data, offset + 52)[0]
        alignment = struct.unpack_from("<I", data, offset + 68)[0]
        require(header_size == 512 and high == 0 and offset + 512 + size <= len(data),
                "Unsupported/truncated MediaTek partition")
        require(0 < alignment <= 4096 and alignment & (alignment - 1) == 0,
                "Invalid declared partition alignment")
        header = data[offset:offset + 512]
        payload = data[offset + 512:offset + 512 + size]
        result.append({"name": name.decode(), "file_offset": hex(offset), "size": size,
                       "declared_alignment": alignment, "header_aligned": offset % alignment == 0,
                       "header_sha256": sha256(header), "payload_sha256": sha256(payload),
                       "image_sha256_zero_padded_16": sha256(payload + bytes((-len(payload)) % 16)),
                       "payload": payload})
    return result


def compare_logo(archive_path):
    require(sha256(archive_path.read_bytes()) == LOGO_ZIP_SHA256, "Unknown logo.zip hash")
    images, manifest = {}, []
    with zipfile.ZipFile(archive_path) as archive:
        for name, digest in MEMBERS.items():
            data = read_member(archive, name)
            require(sha256(data) == digest, "Unexpected logo member hash")
            rows = scan_partitions(data)
            require([r["name"] for r in rows] == ["logo1", "cert1", "cert2", "logo2", "cert1", "cert2"],
                    "Unexpected logo/certificate inventory")
            images[name] = rows
            manifest.append({"name": name, "size": len(data), "sha256": digest})
    stock, repacked, repaired = [images[name] for name in MEMBERS]
    old_cert2, new_cert2 = stock[2]["payload"], repaired[2]["payload"]
    require(new_cert2.endswith(old_cert2), "Repaired cert2 does not preserve donor suffix")
    prefix = new_cert2[:-len(old_cert2)]
    override = read_override(prefix)
    require(len(prefix) == 90 and override["header_sha256"] == repaired[0]["header_sha256"] and
            override["image_sha256"] == repaired[0]["image_sha256_zero_padded_16"],
            "Advertised override hashes do not match repaired logo1")
    return {
        "archive_sha256": LOGO_ZIP_SHA256, "members": manifest,
        "images": {name: [{k: v for k, v in r.items() if k != "payload"} for r in rows]
                   for name, rows in images.items()},
        "logo1": {"modified_payload_retained": repaired[0]["payload"] == repacked[0]["payload"],
                  "cert1_payload_identical_to_donor": repaired[1]["payload"] == stock[1]["payload"],
                  "donor_cert2_preserved_as_suffix": True, "override_prefix_size": len(prefix),
                  "override_prefix_hex": prefix.hex(), "override_hashes": override,
                  "hashes_match_new_header_and_zero_padded_image": True,
                  "plain_unpadded_payload_hash_equals_advertised": repaired[0]["payload_sha256"] == override["image_sha256"],
                  "stock_cert2_contains_stock_header_hash": bytes.fromhex(stock[0]["header_sha256"]) in old_cert2,
                  "stock_cert2_contains_new_header_hash": bytes.fromhex(repaired[0]["header_sha256"]) in old_cert2},
        "repacked_already_has_donor_certificate_payloads": all(repacked[i]["payload"] == stock[i]["payload"]
                                                                for i in [1, 2, 4, 5]),
        "repacked_misaligned_headers": [r["file_offset"] for r in repacked if not r["header_aligned"]],
        "repaired_all_headers_aligned": all(r["header_aligned"] for r in repaired),
        "logo2_payload_and_certificates_unchanged": all(stock[i]["payload"] == repaired[i]["payload"]
                                                      for i in [3, 4, 5]),
        "interpretation": "Observed repair combines a MediaTek context-[0] hash override and container alignment; it is more than copying certificate bytes",
        "uploaded_signing_script_executed": False, "native_mtk_verifier_or_hardware_tested": False,
    }


def audit_qcom_v7(data):
    """Audit the three-segment ABL/UEFI v7 layouts present in supplied CN input."""
    require(data[:7] in [b"\x7fELF\x01\x01\x01", b"\x7fELF\x02\x01\x01"], "Unsupported ELF identification")
    require(len(data) >= (52 if data[4] == 1 else 64), "Truncated ELF header")
    if data[4] == 1:
        h = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
        fmt, expected_ph_size = "<8I", 32
    else:
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        fmt, expected_ph_size = "<IIQQQQQQ", 56
    phoff, phsize, phnum = h[5], h[9], h[10]
    require(phsize == expected_ph_size and phnum == 3 and phoff + phsize * phnum <= len(data),
            "Expected audited three-segment ELF layout")
    headers = []
    for i in range(phnum):
        row = struct.unpack_from(fmt, data, phoff + i * phsize)
        kind, flags, offset, size = (row[0], row[6], row[1], row[4]) if data[4] == 1 else (row[0], row[1], row[2], row[5])
        require(offset + size <= len(data), "ELF segment outside input")
        headers.append((kind, flags, offset, size))
    require([((r[1] >> 24) & 7) for r in headers] == [7, 0, 2], "Unexpected Qualcomm segment ordering")
    hash_offset, hash_size = headers[2][2:]
    require(hash_size >= 64, "Truncated MBN v7 header")
    v7 = struct.unpack_from("<16I", data, hash_offset)
    require(v7[1:8] == (7, 24, 0, 224, 144, 0, 0) and v7[8:10] == (104, 3360) and v7[14] == 3,
            "Unsupported MBN v7 authentication layout")
    table = hash_offset + 64 + v7[4]
    signature_start = table + v7[5]
    certificates_start = signature_start + v7[8]
    require(certificates_start + v7[9] <= hash_offset + hash_size, "Certificates outside hash segment")
    for i, (_, flags, offset, size) in enumerate(headers):
        expected = bytes(48) if (flags >> 24) & 7 == 2 else hashlib.sha384(data[offset:offset + size]).digest()
        require(data[table + i * 48:table + (i + 1) * 48] == expected, "Segment digest mismatch")
    signature_block = data[signature_start:certificates_start]
    tag, _, signature_end = tlv(signature_block)
    require(tag == 0x30 and signature_block[signature_end:] == bytes(len(signature_block) - signature_end),
            "Unexpected signature DER/padding")
    signature = signature_block[:signature_end]
    chain = data[certificates_start:certificates_start + v7[9]]
    cursor, certs = 0, []
    while cursor < len(chain) and chain[cursor] == 0x30:
        require(len(certs) < 8, "Too many certificates")
        tag, _, end = tlv(chain, cursor)
        certs.append(chain[cursor:end])
        cursor = end
    require(len(certs) == 3 and chain[cursor:] == b"\xFF" * (len(chain) - cursor), "Unexpected certificate padding")
    key = x509.load_der_x509_certificate(certs[0]).public_key()
    require(isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp384r1", "Unexpected leaf key")
    signed = data[hash_offset:signature_start]

    def signature_valid(content):
        try:
            key.verify(signature, content, ec.ECDSA(hashes.SHA384()))
            return True
        except InvalidSignature:
            return False

    modified_signed = bytearray(signed)
    modified_signed[table - hash_offset + 48] ^= 1
    report = {"elf_sha256": sha256(data), "elf_class": data[4], "hash_segment_offset": hex(hash_offset),
              "software_id": hex(v7[12]), "signed_range": [hex(hash_offset), hex(signature_start)],
              "signature_offset": hex(signature_start), "signature_der_size": len(signature),
              "certificates_offset": hex(certificates_start), "certificate_sha256": list(map(sha256, certs)),
              "certificate_chain_block_sha256": sha256(chain), "segment_digests_valid": True,
              "original_signature_valid_with_embedded_leaf_key": signature_valid(signed),
              "one_hash_byte_counterfactual_signature_valid": signature_valid(bytes(modified_signed)),
              "counterfactual_is_signature_only_not_a_rebuilt_image": True,
              "trailing_hash_segment_bytes": hash_offset + hash_size - (certificates_start + len(chain))}
    require(report["original_signature_valid_with_embedded_leaf_key"] and
            not report["one_hash_byte_counterfactual_signature_valid"], "Signature calibration differs")
    return report, certs, chain, signature_block


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logo_archive", type=Path)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("generated/logo-comparison"))
    parser.add_argument("--cert-out", type=Path)
    args = parser.parse_args()
    report = compare_logo(args.logo_archive)
    with zipfile.ZipFile(args.firmware) as archive:
        abl = read_member(archive, "cn/abl.elf")
        uefi = read_member(archive, "cn/uefi.elf")
    require(sha256(abl) == "d6e9b4111652bc0067547994a3f8396541383e093aee5d74b154e88f82342309" and
            sha256(uefi) == "1488a82e6735698f84bf0dcf05894723fba5cc2656fa1ed14dd91776b623481a", "Unknown CN input hashes")
    a, certs, chain, signature = audit_qcom_v7(abl)
    u, _, _, _ = audit_qcom_v7(uefi)
    project = Path(__file__).resolve().parent.parent
    candidate = (project / "annibale/OS3.0.307.0.WPKCNXM_abl.elf").read_bytes()
    require(sha256(candidate) == "bbf89327ec2060f83d5e9ec068fd77d2fe2010caee865be176c835bb6dc3447a", "Unknown packaged candidate")
    report["qualcomm"] = {"abl_stock": a, "uefi_stock": u,
        "stock_abl_and_uefi_share_all_three_certificate_bytes": a["certificate_sha256"] == u["certificate_sha256"],
        "packaged_candidate_already_preserves_abl_signature_and_certificates": candidate[0x511B0:] == abl[0x511B0:],
        "copying_certificate_is_not_equivalent_to_a_hash_override_parser": True,
        "device_runtime_authentication_policy_tested": False}
    write_json(args.out / "comparison.json", report)
    if args.cert_out:
        args.cert_out.mkdir(parents=True, exist_ok=True)
        for name, data in zip(["abl_leaf.der", "abl_intermediate.der", "abl_root.der"], certs):
            (args.cert_out / name).write_bytes(data)
        (args.cert_out / "abl_chain_with_padding.bin").write_bytes(chain)
        (args.cert_out / "abl_original_image_signature.bin").write_bytes(signature)
    print("PASS: MediaTek logo repair, preserved Qualcomm certificate bytes and stock ABL/UEFI signatures audited")
    print("NOT TESTED: native MTK parser, Qualcomm bypass or device boot")


if __name__ == "__main__":
    main()
