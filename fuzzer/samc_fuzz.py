#!/usr/bin/env python3
"""
samc_fuzz.py — stateful samc-protocol fuzzer for CodeMeterLin.

Architecture
------------
  1. Connect to the live daemon on TCP 127.0.0.1:22350.
  2. Replay a captured session up to "fuzz target frame N", substituting
     any session IDs that the daemon freshly issued during this replay.
  3. Mutate frame N's plaintext (bit-flips, byte-flips, length twiddles,
     dict splice).
  4. Encrypt + send the mutated frame.
  5. Read and decrypt any response; log.
  6. Close; check whether the daemon is still alive.

A crash = daemon pid gone, or a new coredump under /var/lib/systemd/
coredump/, or daemon stops accepting new connections.

Run as user `daemon` (or root) so access to /var/lib/CodeMeter is
uncoloured.  Real daemon must be running via systemctl.

Reusable crypto is imported from ax_decrypt/main/research_scripts/
mitm_app_daemon.py.
"""
import argparse
import glob
import hashlib
import os
import pathlib
import random
import select
import socket
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

# --- crypto (inlined from mitm_app_daemon.py for standalone-ness) -----
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def magic_div_1009(eax: int) -> int:
    eax = (eax * 1000) & 0xFFFFFFFF
    rcx = ((eax * 0x3CE4585) >> 32) & 0xFFFFFFFF
    eax = (eax - rcx) & 0xFFFFFFFF
    eax >>= 1
    eax = (eax + rcx) & 0xFFFFFFFF
    return eax >> 9


def derive_session_key_iv(t: int) -> tuple[bytes, bytes]:
    d = hashlib.sha1(struct.pack("<I", magic_div_1009(t))).digest()
    return d[:16], d[4:20]


def _cts_shuffle(ct: bytes) -> bytes:
    if len(ct) < 32:
        return ct
    return ct[:-32] + ct[-16:] + ct[-32:-16]


def _cts_unshuffle(ct: bytes) -> bytes:
    if len(ct) < 32:
        return ct
    return ct[:-32] + ct[-16:] + ct[-32:-16]


def build_mac_suffix(data: bytes) -> bytes:
    aligned = ((len(data) + 16) + 15) & ~15
    if aligned < 32:
        aligned = 32
    pad = aligned - len(data) - 8
    return data + b"\x00" * pad + struct.pack("<I", len(data)) + struct.pack("<I", zlib.crc32(data))


def encrypt_c2d_frame(plaintext: bytes, t: int) -> bytes:
    """Build a wire frame (samc header + 0xa0 + cipher)."""
    full_pt = build_mac_suffix(plaintext)
    key, iv = derive_session_key_iv(t)
    ct_pure = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(full_pt)
    wire_ct = _cts_shuffle(ct_pure)
    body = b"\xa0" + wire_ct
    hdr = b"samc" + struct.pack("<I", len(body)) + bytes([0x11, 0, 1, 0, 0, 0, 0, 0])
    return hdr + body


def decrypt_d2c_frame(wire: bytes, t: int) -> bytes | None:
    """Try decrypting a D→C frame.  Returns the inner plaintext data (post-tail-strip)
    or None if the CRC doesn't verify within a small time window."""
    if len(wire) < 16 or wire[:4] != b"samc":
        return None
    body_len = struct.unpack("<I", wire[4:8])[0]
    if len(wire) != 16 + body_len:
        return None
    body = wire[16:]
    # D→C has no opcode byte
    if len(body) < 32 or len(body) % 16 != 0:
        return None
    # Wider window: bucket boundaries can fall inside a session (each
    # bucket = ~1009s but they don't align nicely with wall-clock seconds).
    for dt in range(-30, 31):
        key, iv = derive_session_key_iv(t + dt)
        pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(_cts_unshuffle(body))
        length = struct.unpack("<I", pt[-8:-4])[0]
        crc = struct.unpack("<I", pt[-4:])[0]
        if 0 <= length <= len(pt) - 8 and zlib.crc32(pt[:length]) == crc:
            return pt[:length]
    return None


def recv_exact(s: socket.socket, n: int, timeout: float = 2.0) -> bytes:
    s.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = s.recv(n - len(buf))
        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def recv_one_wire_frame(s: socket.socket, timeout: float = 2.0) -> bytes | None:
    hdr = recv_exact(s, 16, timeout)
    if len(hdr) != 16 or hdr[:4] != b"samc":
        return None
    body_len = struct.unpack("<I", hdr[4:8])[0]
    if body_len > 1 << 20:    # 1 MB sanity cap
        return None
    body = recv_exact(s, body_len, timeout)
    if len(body) != body_len:
        return None
    return hdr + body


# --- captured session plaintexts ---------------------------------------
# Canonical bytes auto-extracted from a fresh testbench session via mitm.
# See samc_session_data.py.
from samc_session_data import CAPTURED_C2D as CAPTURED_SESSION_C2D

# For each C2D frame, list (offset, 4B-of-SID) positions that must be
# patched at runtime with the current daemon-issued SID.  SID index tells
# which D→C response we pull the SID from (0 = first D→C after HELLO).
# `None` means no SID patch needed.
#
# Derived from comparing two captured sessions and looking for the
# 4-byte windows that differ.
SID_PATCHES = [
    None,              # 0: HELLO — no SID
    [(4, 0)],          # 1: ACK — embed SID0 at offset 4
    None,              # 2: 0x64 BIG — no SID embedding observed
]


def apply_sid_patches(frame_idx: int, plaintext: bytes, sids: list[bytes]) -> bytes:
    """Patch the plaintext of frame_idx with the current session's SIDs."""
    patches = SID_PATCHES[frame_idx]
    if not patches:
        return plaintext
    pt = bytearray(plaintext)
    for off, sid_idx in patches:
        if sid_idx < len(sids):
            pt[off:off + 4] = sids[sid_idx]
    return bytes(pt)


# Per-session client token inside HELLO: bytes 28-31, used again inside the
# 0x64 BIG message. Daemon rejects replayed tokens, so we pick a fresh random
# value per session and substitute it in every frame that embeds it.
HELLO_TOKEN_OFFSET = 28
HELLO_TOKEN_LEN = 4

# In the 0x64 BIG message (frame 2), the same token appears partway through.
# Locate it from the captured plaintext once at import time.
_BIG = CAPTURED_SESSION_C2D[2]
_ORIG_TOKEN = CAPTURED_SESSION_C2D[0][HELLO_TOKEN_OFFSET:HELLO_TOKEN_OFFSET + HELLO_TOKEN_LEN]
BIG_TOKEN_OFFSETS = []
off = 0
while True:
    found = _BIG.find(_ORIG_TOKEN, off)
    if found < 0:
        break
    BIG_TOKEN_OFFSETS.append(found)
    off = found + 1


def substitute_token(frame_idx: int, plaintext: bytes, token: bytes) -> bytes:
    """Substitute the per-session client token into frames that embed it."""
    pt = bytearray(plaintext)
    if frame_idx == 0:   # HELLO
        pt[HELLO_TOKEN_OFFSET:HELLO_TOKEN_OFFSET + HELLO_TOKEN_LEN] = token
    elif frame_idx == 2:  # 0x64 BIG — same token appears at each match
        for o in BIG_TOKEN_OFFSETS:
            pt[o:o + HELLO_TOKEN_LEN] = token
    return bytes(pt)


# --- mutators ----------------------------------------------------------
DICT_TOKENS = [
    b"samc",
    b"\x26\x8e\x5b\x00",          # firm code
    b"\x0a\x00\x00\x00", b"\x0b\x00\x00\x00", b"\x21\x00\x00\x00",
    b"\x64\x00\x00\x00", b"\x23\x00\x00\x00", b"\x5a\x00\x00\x00",
    b"\x69\x00\x00\x00",
    b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x00\x00\x00\x80",
    b"\x01\x00\x00\x00",
    b"CodeMeter", b"W\x00I\x00B\x00U\x00",
]


def mutate(plaintext: bytes, rng: random.Random) -> bytes:
    """Apply a random mutation strategy."""
    if not plaintext:
        # Grow empty inputs
        return rng.randbytes(rng.randint(4, 64))

    strategy = rng.choice([
        "bitflip", "byteflip", "insert_rand", "delete",
        "extend_zero", "truncate", "dict_splice",
        "sentinel_byte",
    ])
    pt = bytearray(plaintext)

    if strategy == "bitflip" and pt:
        pos = rng.randrange(len(pt))
        pt[pos] ^= 1 << rng.randrange(8)
    elif strategy == "byteflip" and pt:
        pos = rng.randrange(len(pt))
        pt[pos] = rng.randrange(256)
    elif strategy == "insert_rand":
        pos = rng.randrange(len(pt) + 1)
        n = rng.randint(1, 16)
        pt[pos:pos] = rng.randbytes(n)
    elif strategy == "delete" and len(pt) > 1:
        pos = rng.randrange(len(pt))
        n = rng.randint(1, min(16, len(pt) - pos))
        del pt[pos:pos + n]
    elif strategy == "extend_zero":
        n = rng.randint(1, 64)
        pt.extend(b"\x00" * n)
    elif strategy == "truncate" and len(pt) > 1:
        pt = pt[: rng.randrange(1, len(pt))]
    elif strategy == "dict_splice":
        token = rng.choice(DICT_TOKENS)
        pos = rng.randrange(len(pt) + 1)
        pt[pos:pos] = token
    elif strategy == "sentinel_byte" and pt:
        pos = rng.randrange(len(pt))
        pt[pos] = rng.choice([0x00, 0xff, 0x7f, 0x80, 0x01])
    return bytes(pt)


# --- session replay + fuzz driver --------------------------------------
def run_iteration(daemon_host: str, daemon_port: int, target_frame: int,
                  rng: random.Random, log_f) -> tuple[str, bytes]:
    """Replay the captured session up to `target_frame`, mutate that
    frame's plaintext, send it, return (status, mutated_plaintext).
    Status = 'ok' | 'closed_early' | 'conn_error' | 'no_response'.
    """
    sids: list[bytes] = []
    # Fresh per-session client token so the daemon doesn't reject us as a replay
    token = rng.randbytes(HELLO_TOKEN_LEN)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((daemon_host, daemon_port))
    except OSError as e:
        return f"conn_error:{e}", b""

    try:
        for idx in range(target_frame + 1):
            pt = CAPTURED_SESSION_C2D[idx]
            pt = substitute_token(idx, pt, token)
            pt = apply_sid_patches(idx, pt, sids)
            if idx == target_frame:
                pt = mutate(pt, rng)

            wire = encrypt_c2d_frame(pt, int(time.time()))
            try:
                sock.sendall(wire)
            except (OSError, ConnectionResetError, BrokenPipeError):
                return "closed_early", pt

            # After sending, the daemon may or may not respond with a D→C
            # frame.  For the "real" frames we captured, it always did
            # with a short 8B or 32B response.
            try:
                resp = recv_one_wire_frame(sock, timeout=1.5)
            except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
                resp = None
            if resp is None:
                if idx < target_frame:
                    return "no_response", pt
                return "ok", pt   # target frame sent, no reply is fine

            inner = decrypt_d2c_frame(resp, int(time.time()))
            if inner is None:
                if idx < target_frame:
                    return "decrypt_fail", pt
                return "ok", pt
            # Extract the 4-byte SID (last 4 of the first 8 plaintext bytes)
            if len(inner) >= 8:
                sid = bytes(inner[4:8])
                sids.append(sid)
        return "ok", pt
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- crash detection ---------------------------------------------------
def get_daemon_pid() -> int | None:
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "/usr/sbin/CodeMeterLin -f"], text=True, timeout=1
        )
        pids = [int(p) for p in out.split() if p.isdigit()]
        # Exclude fuzzer-related daemons (afl-qemu-trace children)
        for p in pids:
            cmd = Path(f"/proc/{p}/cmdline").read_bytes().replace(b"\x00", b" ").strip()
            if b"afl-qemu" in cmd:
                continue
            return p
    except Exception:
        pass
    return None


def newest_coredump() -> str | None:
    try:
        files = sorted(
            glob.glob("/var/lib/systemd/coredump/core.CodeMeter*"),
            key=os.path.getmtime,
        )
        return files[-1] if files else None
    except Exception:
        return None


# --- main --------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--iterations", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--target-frame", type=int, default=-1,
                    help="Which frame to mutate; -1 = rotate")
    ap.add_argument("--out-dir", default="/home/avj/clones/ax_fuzz/output/samc_fuzz")
    ap.add_argument("--log-every", type=int, default=50)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    out = Path(args.out_dir)
    (out / "crashes").mkdir(parents=True, exist_ok=True)
    (out / "interesting").mkdir(parents=True, exist_ok=True)
    log_path = out / "fuzz.log"
    log_f = log_path.open("a")

    baseline_pid = get_daemon_pid()
    baseline_core = newest_coredump()
    print(f"[start] daemon_pid={baseline_pid}  iterations={args.iterations}")
    log_f.write(f"[start] daemon_pid={baseline_pid} t={int(time.time())}\n")
    log_f.flush()

    n_frames = len(CAPTURED_SESSION_C2D)
    start = time.time()
    status_counts: dict[str, int] = {}
    for i in range(args.iterations):
        if args.target_frame >= 0:
            tf = args.target_frame
        else:
            # rotate across frames so every handler gets fuzzed
            tf = i % n_frames
        try:
            status, mutated = run_iteration(args.host, args.port, tf, rng, log_f)
        except Exception as e:
            status, mutated = f"exc:{type(e).__name__}", b""
        status_counts[status] = status_counts.get(status, 0) + 1

        # Crash check every 10 iterations (expensive)
        if i % 10 == 9:
            cur_pid = get_daemon_pid()
            cur_core = newest_coredump()
            if cur_pid != baseline_pid or cur_core != baseline_core:
                ts = int(time.time())
                crash_bin = out / "crashes" / f"crash_{ts}_f{tf}.bin"
                crash_bin.write_bytes(mutated)
                log_f.write(f"[CRASH] t={ts} frame={tf} pid_was={baseline_pid} "
                            f"pid_now={cur_pid} core_was={baseline_core} "
                            f"core_now={cur_core}\n")
                log_f.flush()
                print(f"*** CRASH detected at iter {i} frame {tf}: {crash_bin} ***")
                # Try to restart daemon ourselves so the campaign continues.
                # Use flock so concurrent workers don't all restart simultaneously.
                if not get_daemon_pid():
                    try:
                        subprocess.run(
                            ["flock", "-w", "60", "/tmp/samc_restart.lock", "-c",
                             "sudo -n rm -f /var/lock/cm_lock; "
                             "sudo -n systemctl restart codemeter; "
                             "sleep 2"],
                            check=False, timeout=120)
                    except subprocess.TimeoutExpired:
                        pass    # another worker is doing it; we'll just wait below
                # Wait up to 30 s for daemon to reappear.
                for _ in range(30):
                    cur_pid = get_daemon_pid()
                    if cur_pid:
                        break
                    time.sleep(1)
                baseline_pid = cur_pid
                baseline_core = newest_coredump()

        if i % args.log_every == args.log_every - 1:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            print(f"[{i + 1}/{args.iterations}] {elapsed:.0f}s  {rate:.1f} it/s  {status_counts}")
            log_f.write(f"[prog] i={i + 1} elapsed={elapsed:.0f}s {status_counts}\n")
            log_f.flush()

    print(f"[done] {status_counts}")
    log_f.close()


if __name__ == "__main__":
    main()
