#!/usr/bin/env python3
"""
samc_replay.py — given a saved crash input, replay it once and see whether
the daemon crashes. Used to estimate deterministic reproducibility.

Usage: samc_replay.py <crash_file> [<crash_file> ...]
"""
import os
import sys
import socket
import time
import random
sys.path.insert(0, "/home/avj/clones/ax_fuzz/tier1")
from samc_fuzz import (CAPTURED_SESSION_C2D, encrypt_c2d_frame,
                        recv_one_wire_frame, decrypt_d2c_frame,
                        substitute_token, apply_sid_patches, HELLO_TOKEN_LEN)


def daemon_pid():
    import subprocess
    try:
        out = subprocess.check_output(["pgrep", "-f", "/usr/sbin/CodeMeterLin -f"],
                                      text=True, timeout=1)
        for p in out.split():
            if p.isdigit():
                return int(p)
    except Exception:
        pass
    return None


def replay_one(crash_file: str) -> str:
    """Replay HELLO+ACK normally then send the crash input. Returns
    'crash'|'no_crash'|'conn_err'."""
    target_frame = int(os.path.basename(crash_file).rsplit('_f', 1)[1].rsplit('.', 1)[0])
    payload = open(crash_file, "rb").read()

    pid_before = daemon_pid()
    if pid_before is None:
        return "daemon_down"

    # Reuse a fixed token to keep things deterministic for this replay.
    token = b"\xab\xcd\x01\x02"
    sids = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", 22350))
        for idx in range(target_frame + 1):
            if idx < target_frame:
                pt = CAPTURED_SESSION_C2D[idx]
                pt = substitute_token(idx, pt, token)
                pt = apply_sid_patches(idx, pt, sids)
            else:
                pt = payload
            wire = encrypt_c2d_frame(pt, int(time.time()))
            s.sendall(wire)
            if idx < target_frame:
                resp = recv_one_wire_frame(s, 1.5)
                if resp:
                    inner = decrypt_d2c_frame(resp, int(time.time()))
                    if inner and len(inner) >= 8:
                        sids.append(bytes(inner[4:8]))
        s.close()
    except OSError:
        pass

    # Was daemon killed?
    time.sleep(0.5)
    pid_after = daemon_pid()
    if pid_after is None or pid_after != pid_before:
        return "crash"
    return "no_crash"


def main():
    files = sys.argv[1:]
    counts = {}
    for f in files:
        r = replay_one(f)
        counts[r] = counts.get(r, 0) + 1
        print(f"{r:<10} {f}")
    print()
    print(f"Summary: {counts}")


if __name__ == "__main__":
    main()
