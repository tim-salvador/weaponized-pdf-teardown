#!/usr/bin/env python3
"""Statically unwrap evil.pdf to the deobfuscated pyherion payload.

Carve the embedded FlateDecode stream, decompress it to the PyInstaller PE,
locate the pyherion entry script, extract its AES-256-ECB key and ciphertext,
and print the decrypted source.

This script only reads and decrypts. It never calls exec(), never writes an
executable, and never opens a network connection. Point it at your own copy of
the sample; the binary is not distributed with this repo.

Usage:
    python3 decrypt_pyherion.py /path/to/evil.pdf

Requires: Python 3.9+ and the `cryptography` package.
"""
import base64
import re
import sys
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The pyherion stub is an exec() of a base64 literal. Matching this shape, not a
# generic substring, is what distinguishes the real entry script from the
# bundled AES module's compiled docstring (which also mentions the cipher).
PYHERION_STUB = re.compile(rb'exec\([A-Za-z0-9_]+\("[A-Za-z0-9+/=]{40,}"\)\)')


def carve_embedded_stream(pdf: bytes) -> bytes:
    """Return the decompressed bytes of the /EmbeddedFile stream (object 51).

    The object declares its own compressed /Length, so slice by that rather
    than scanning for endstream, which is unreliable on a PDF with no newlines.
    """
    obj = pdf.find(b"51 0 obj")
    if obj < 0:
        raise SystemExit("object 51 (/EmbeddedFile) not found")
    length_match = re.search(rb"/Length\s+(\d+)", pdf[obj:obj + 400])
    if not length_match:
        raise SystemExit("could not read /Length of embedded stream")
    length = int(length_match.group(1))

    start = pdf.find(b"stream", obj) + len(b"stream")
    while pdf[start] in (13, 10):  # skip the CR/LF after the stream keyword
        start += 1
    return zlib.decompress(pdf[start:start + length])


def extract_pyherion_source(entry_script: bytes) -> str:
    """Peel the pyherion layers and return the decrypted payload source.

    Layer 1: outer base64 blob passed to exec().
    Layer 2: AES-256-ECB decrypt with an embedded key, then rstrip('{').
    """
    text = entry_script.decode("latin-1")

    outer_b64 = re.search(r'exec\([A-Za-z0-9_]+\("([A-Za-z0-9+/=]+)"\)\)', text)
    if not outer_b64:
        raise SystemExit("outer base64 exec blob not found")
    layer1 = base64.b64decode(outer_b64.group(1)).decode("latin-1")

    key = re.search(r'\.new\("([^"]+)"\)', layer1)
    ct = re.search(r'decrypt\([A-Za-z0-9_]+\("([A-Za-z0-9+/=]+)"\)\)', layer1)
    if not (key and ct):
        raise SystemExit("could not locate AES key or ciphertext in layer 1")

    key_bytes = key.group(1).encode("latin-1")
    ciphertext = base64.b64decode(ct.group(1))
    if len(ciphertext) % 16:
        raise SystemExit("ciphertext is not a multiple of the AES block size")

    decryptor = Cipher(algorithms.AES(key_bytes), modes.ECB()).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.rstrip(b"{").decode("latin-1")


def find_entry_script(pe: bytes) -> bytes:
    """Return the pyherion entry script from the PyInstaller image.

    PyInstaller stores source entries (TOC type 's') zlib-compressed inside the
    appended CArchive, so the plaintext does not appear in the PE directly.
    Select the member by the pyherion signature itself (an exec() of a base64
    literal) rather than a loose substring, which would also match the bundled
    AES module's compiled docstring. Check the raw image first in case a build
    stored the script uncompressed. This avoids parsing the TOC and needs no
    PyInstaller-aware tooling.
    """
    if PYHERION_STUB.search(pe):
        return pe
    for pos in _zlib_header_positions(pe):
        try:
            blob = zlib.decompressobj().decompress(pe[pos:])
        except zlib.error:
            continue
        if PYHERION_STUB.search(blob):
            return blob
    raise SystemExit("pyherion entry script not found among compressed members")


def _zlib_header_positions(data: bytes):
    """Yield offsets of likely zlib stream starts (0x78 with a valid check)."""
    for pos in range(len(data) - 1):
        if data[pos] == 0x78 and data[pos + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            # zlib header check: (CMF << 8 | FLG) must be a multiple of 31.
            if (((data[pos] << 8) | data[pos + 1]) % 31) == 0:
                yield pos


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} /path/to/evil.pdf")

    with open(sys.argv[1], "rb") as fh:
        pdf = fh.read()

    pe = carve_embedded_stream(pdf)
    if pe[:2] != b"MZ":
        raise SystemExit("decompressed payload is not a PE (expected MZ header)")

    entry = find_entry_script(pe)
    source = extract_pyherion_source(entry)

    print("# --- decrypted pyherion payload (NOT executed) ---")
    print(source)


if __name__ == "__main__":
    main()
