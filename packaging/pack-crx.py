#!/usr/bin/env python3
"""Pack an unpacked browser extension into a signed CRX3 file.

Chrome's own `--pack-extension` writes the file next to the extension and
cannot run inside a Flatpak sandbox, so AuraPass carries a tiny, dependency-free
implementation of the documented CRX3 container instead:

    "Cr24" | u32 version=3 | u32 header length | CrxFileHeader | zip

`CrxFileHeader` is protobuf:

    message AsymmetricKeyProof { bytes public_key = 1; bytes signature = 2; }
    message CrxFileHeader {
        repeated AsymmetricKeyProof sha256_with_rsa = 2;
        bytes signed_header_data = 10000;   # SignedData { bytes crx_id = 1; }
    }

The RSA-SHA256 signature covers

    "CRX3 SignedData\\0" | u32(len(signed_header_data)) | signed_header_data | zip

which is exactly what Chrome verifies before loading the extension.

Usage:
    pack-crx.py --dir extensions/chromium --key packaging/keys/chromium.pem \\
                --out dist/aurapass-chromium-1.0.4.crx

The key is created (2048-bit RSA) when it does not exist. Keep it: the
extension id and therefore updates are derived from it.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

MAGIC = b"Cr24"
SIGNED_PREFIX = b"CRX3 SignedData\x00"


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field(number: int, payload: bytes) -> bytes:
    """A length-delimited protobuf field."""
    return varint((number << 3) | 2) + varint(len(payload)) + payload


def zip_extension(directory: Path) -> bytes:
    """Deterministic zip of the extension, manifest first."""
    files = sorted(
        path for path in directory.rglob("*")
        if path.is_file() and not path.name.startswith(".")
    )
    with tempfile.TemporaryFile() as buffer:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in files:
                info = zipfile.ZipInfo(str(path.relative_to(directory)))
                info.date_time = (2020, 1, 1, 0, 0, 0)
                info.external_attr = 0o644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes())
        buffer.seek(0)
        return buffer.read()


def ensure_key(path: Path) -> bytes:
    """Create the RSA key if needed and return its SPKI DER public key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        subprocess.run(
            ["openssl", "genrsa", "-out", str(path), "2048"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        os.chmod(path, 0o600)
    return subprocess.run(
        ["openssl", "rsa", "-in", str(path), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout


def sign(key: Path, payload: bytes) -> bytes:
    with tempfile.NamedTemporaryFile() as message:
        message.write(payload)
        message.flush()
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(key), message.name],
            check=True,
            capture_output=True,
        ).stdout


def extension_id(public_key: bytes) -> str:
    """Chrome's id: first 16 bytes of SHA-256(SPKI), each nibble mapped a-p."""
    digest = hashlib.sha256(public_key).hexdigest()[:32]
    return "".join(chr(ord("a") + int(nibble, 16)) for nibble in digest)


def pack(directory: Path, key_path: Path) -> tuple[bytes, str]:
    public_key = ensure_key(key_path)
    archive = zip_extension(directory)

    crx_id = hashlib.sha256(public_key).digest()[:16]
    signed_header_data = field(1, crx_id)
    payload = (
        SIGNED_PREFIX
        + struct.pack("<I", len(signed_header_data))
        + signed_header_data
        + archive
    )
    proof = field(1, public_key) + field(2, sign(key_path, payload))
    header = field(2, proof) + field(10000, signed_header_data)

    crx = MAGIC + struct.pack("<II", 3, len(header)) + header + archive
    return crx, extension_id(public_key)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    if not (args.dir / "manifest.json").is_file():
        print(f"{args.dir} has no manifest.json", file=sys.stderr)
        return 2

    crx, ident = pack(args.dir, args.key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(crx)
    print(f"  {args.out} ({len(crx) / 1024:.1f} KiB, id {ident})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
