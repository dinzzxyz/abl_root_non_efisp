"""Read-only helpers for the supplied Qualcomm firmware; no device I/O."""
from __future__ import annotations

import contextlib
import hashlib
import io
import lzma
import re
import struct
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pefile

MAX_BLOB = 64 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > MAX_BLOB:
        raise ValueError(f"Archive member exceeds analysis limit: {name}")
    if info.flag_bits & 1:
        raise ValueError(f"Encrypted archive member: {name}")
    return archive.read(info)


def expanded_blobs(raw: bytes):
    """Yield raw bytes and bounded, deduplicated LZMA-alone expansions.

    This is an extraction heuristic for these images, not a complete firmware
    parser. No absence-of-a-marker result proves absence of executable code.
    """
    seen = set()
    queue = [("raw", raw, 0)]
    while queue:
        origin, blob, depth = queue.pop(0)
        digest = sha256(blob)
        if digest in seen:
            continue
        seen.add(digest)
        yield origin, blob
        if depth >= 3:
            continue
        for match in re.finditer(b"\x5d\x00\x00", blob):
            offset = match.start()
            try:
                dec = lzma.LZMADecompressor(
                    format=lzma.FORMAT_ALONE, memlimit=MAX_BLOB
                )
                value = dec.decompress(blob[offset:], max_length=MAX_BLOB + 1)
                if dec.eof and 256 < len(value) <= MAX_BLOB:
                    queue.append((f"{origin}/lzma@0x{offset:x}", value, depth + 1))
            except (lzma.LZMAError, EOFError):
                pass


@dataclass
class PeImage:
    data: bytes
    origin: str
    blob_offset: int

    def metadata(self):
        pe = pefile.PE(data=self.data, fast_load=True)
        markers = {}
        for term in ("efisp", "Loading GBL app", "Starting GBL app",
                     "LoadImageNoAuthWrapper", "LinuxLoader", "BOOTENTRIES"):
            found = {}
            for enc in ("ascii", "utf-16le"):
                offsets = [hex(m.start()) for m in re.finditer(
                    re.escape(term.encode(enc)), self.data)]
                if offsets:
                    found[enc] = offsets
            markers[term] = found
        return {
            "sha256": sha256(self.data), "size_bytes": len(self.data),
            "origin": self.origin, "blob_offset": hex(self.blob_offset),
            "machine": hex(pe.FILE_HEADER.Machine),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "entry_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase), "markers": markers,
        }


def pe_images(raw: bytes) -> list[PeImage]:
    result = {}
    for origin, blob in expanded_blobs(raw):
        for match in re.finditer(b"MZ", blob):
            offset = match.start()
            if offset + 0x40 > len(blob):
                continue
            peoff = struct.unpack_from("<I", blob, offset + 0x3C)[0]
            if (peoff > len(blob) - offset - 24 or
                    blob[offset + peoff:offset + peoff + 4] != b"PE\0\0"):
                continue
            try:
                pe = pefile.PE(data=blob[offset:], fast_load=True)
                if not 1 <= pe.FILE_HEADER.NumberOfSections <= 96:
                    continue
                end = max([pe.OPTIONAL_HEADER.SizeOfHeaders] + [
                    s.PointerToRawData + s.SizeOfRawData for s in pe.sections])
                if end > len(blob) - offset or end < 0x100:
                    continue
                data = blob[offset:offset + end]
                result.setdefault(sha256(data), PeImage(data, origin, offset))
            except (pefile.PEFormatError, ValueError, struct.error):
                pass
    return list(result.values())


def largest_pe(raw: bytes) -> PeImage:
    candidates = pe_images(raw)
    if not candidates:
        raise ValueError("No supported PE image found")
    return max(candidates, key=lambda p: len(p.data))


def fdt_properties(raw: bytes) -> list[dict]:
    """Decode bounded FDT records; offsets refer to the original input file."""
    result = []
    for match in re.finditer(b"\xd0\x0d\xfe\xed", raw):
        base = match.start()
        try:
            header = struct.unpack_from(">10I", raw, base)
            _, total, os_, ot, _, version, _, _, ns, nb = header
            if not (16 <= version <= 17 and 40 <= total <= len(raw) - base):
                continue
            if os_ + nb > total or ot + ns > total:
                continue
            blob = raw[base:base + total]
            strings = blob[ot:ot + ns]
            pos, stack, rows = os_, [], []
            while pos + 4 <= os_ + nb:
                token = struct.unpack_from(">I", blob, pos)[0]
                pos += 4
                if token == 1:
                    end = blob.index(b"\0", pos, os_ + nb)
                    stack.append(blob[pos:end].decode("utf-8"))
                    pos = (end + 4) & ~3
                elif token == 2:
                    stack.pop()
                elif token == 3:
                    size, keyoff = struct.unpack_from(">II", blob, pos)
                    pos += 8
                    if pos + size > os_ + nb:
                        raise ValueError("Truncated FDT property")
                    keyend = strings.index(b"\0", keyoff)
                    key = strings[keyoff:keyend].decode("utf-8")
                    value, value_offset = blob[pos:pos + size], base + pos
                    pos = (pos + size + 3) & ~3
                    text = None
                    if value.endswith(b"\0"):
                        parts = value.rstrip(b"\0").split(b"\0")
                        if parts and all(all(32 <= c < 127 for c in p) for p in parts):
                            text = [p.decode("ascii") for p in parts]
                    rows.append({
                        "dtb_offset": hex(base), "path": "/".join(stack),
                        "key": key, "value_offset": hex(value_offset),
                        "raw_hex": value.hex(), "strings": text,
                        "cells_be": [hex(x) for x in struct.unpack(
                            ">" + str(size // 4) + "I", value)]
                            if size and size % 4 == 0 else None,
                    })
                elif token == 4:
                    continue
                elif token == 9:
                    result.extend(rows)
                    break
                else:
                    raise ValueError("Invalid FDT token")
        except (ValueError, IndexError, struct.error, UnicodeDecodeError):
            continue
    return result


def named_firmware_files(raw: bytes):
    """Read FV/FFS UI names using the independent uefi_firmware parser."""
    from uefi_firmware.uefi import FirmwareFile, FirmwareVolume

    for match in re.finditer(b"_FVH", raw):
        base = match.start() - 0x28
        if base < 0:
            continue
        fv = FirmwareVolume(raw[base:])
        with contextlib.redirect_stdout(io.StringIO()):
            if not fv.process():
                continue
        seen = set()

        def visit(obj):
            if id(obj) in seen:
                return
            seen.add(id(obj))
            if isinstance(obj, FirmwareFile):
                names = [s.data.decode("utf-16le", errors="replace").rstrip("\0")
                         for s in obj.sections if s.type == 0x15]
                yield obj, "|".join(names), str(uuid.UUID(bytes_le=obj.guid))
            for child in getattr(obj, "objects", []) or []:
                yield from visit(child)

        yield from visit(fv)


def write_json(path: Path, value):
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
