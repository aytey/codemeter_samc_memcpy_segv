#!/usr/bin/env python3
"""Remote CodeMeter daemon-to-server protocol fuzz launcher.

This targets the protocol spoken between a local CodeMeter daemon and a
remote CodeMeter server, not the local app-to-daemon SAMC protocol used by
repro_prefixed_hello.py.  Each worker connects directly to the remote server,
performs the ECDH wrapper handshake, then fuzzes selected encrypted records.

Crash detection is intentionally remote: a small Python monitor is run over
SSH on the target host and reports CodeMeterLin PID/starttime or core-file
changes.  Workers keep only in-memory rings on the hot path and dump those
rings when the controller stops.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import importlib.util
import json
import multiprocessing as mp
import os
import queue
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import zlib
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
DEFAULT_HELPER_DIR = Path("/home/avj/clones/ax_decrypt/009/research_scripts")

INTERESTING_TYPES = [
    0x00, 0x0A, 0x0B, 0x20, 0x21, 0x23, 0x31, 0x5A,
    0x5E, 0x64, 0x69, 0x76, 0xA1, 0xA2, 0xDD, 0xFF,
]
INTERESTING_QTYPES = [
    0x00, 0x01, 0x03, 0x0B, 0x20, 0x21, 0x23, 0x31,
    0x33, 0x37, 0x5A, 0x5E, 0x64, 0x69, 0x76, 0xFF,
    0x0100, 0x1000, 0xFFFF, 0xFFFFFFFF,
]
INTERESTING_SIZES = [
    0x00, 0x01, 0x08, 0x0F, 0x10, 0x11, 0x20, 0x30,
    0x40, 0x80, 0x90, 0xA0, 0x100, 0x220, 0x400, 0x1000,
    0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
]
INTERESTING_LENGTHS = [
    0x00, 0x01, 0x08, 0x0F, 0x10, 0x11, 0x20, 0x30,
    0x90, 0x220, 0xFFFF, 0xFFFFFFFF,
]


REMOTE_MONITOR_BODY = r'''
import glob
import json
import os
import subprocess
import time


def emit(obj):
    print(json.dumps(obj, sort_keys=True), flush=True)


def pgrep_codemeter():
    try:
        out = subprocess.run(
            ["pgrep", "-x", "CodeMeterLin"],
            check=False, capture_output=True, text=True, timeout=2.0,
        )
    except Exception as exc:
        return {"error": repr(exc), "pids": []}
    pids = []
    for tok in (out.stdout or "").split():
        try:
            pids.append(int(tok))
        except ValueError:
            pass
    return {"error": None, "pids": sorted(pids)}


def proc_start_ticks(pid):
    try:
        text = open(f"/proc/{pid}/stat", "r", encoding="utf-8").read()
        after_comm = text.rsplit(")", 1)[1].split()
        return int(after_comm[19])
    except Exception:
        return None


def daemon_state():
    raw = pgrep_codemeter()
    states = []
    for pid in raw["pids"]:
        states.append({"pid": pid, "start_ticks": proc_start_ticks(pid)})
    return {
        "pgrep_error": raw["error"],
        "pids": states,
        "pid_key": [[s["pid"], s["start_ticks"]] for s in states],
    }


def core_state():
    patterns = []
    for root in CORE_DIRS:
        patterns.extend([
            os.path.join(root, "*CodeMeter*"),
            os.path.join(root, "core*"),
        ])
    seen = set()
    files = []
    for pat in patterns:
        for path in glob.glob(pat):
            if path in seen:
                continue
            seen.add(path)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if not os.path.isfile(path):
                continue
            files.append({
                "path": path,
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
            })
    files.sort(key=lambda x: (x["mtime_ns"], x["path"]))
    latest = files[-1] if files else None
    return {
        "count": len(files),
        "latest": latest,
        "key": [
            len(files),
            latest["path"] if latest else None,
            latest["size"] if latest else None,
            latest["mtime_ns"] if latest else None,
        ],
    }


def snapshot():
    return {"daemon": daemon_state(), "cores": core_state()}


def main():
    baseline = snapshot()
    emit({"event": "baseline", "state": baseline, "time": time.time()})
    base_pid_key = baseline["daemon"]["pid_key"]
    base_core_key = baseline["cores"]["key"]
    while True:
        time.sleep(INTERVAL)
        cur = snapshot()
        reasons = []
        if cur["daemon"]["pid_key"] != base_pid_key:
            reasons.append("pid_changed")
        if cur["cores"]["key"] != base_core_key:
            reasons.append("core_changed")
        if reasons:
            emit({
                "event": "change",
                "reasons": reasons,
                "baseline": baseline,
                "state": cur,
                "time": time.time(),
            })
            return


if __name__ == "__main__":
    main()
'''


def now_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def json_dump(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def load_v7(helper_dir: Path):
    helper = helper_dir / "cm_direct_client_v7.py"
    if not helper.exists():
        raise FileNotFoundError(f"missing helper: {helper}")
    if str(helper_dir) not in sys.path:
        sys.path.insert(0, str(helper_dir))
    spec = importlib.util.spec_from_file_location("cm_direct_client_v7_remote_fuzz", helper)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import helper: {helper}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def validate_helper_dir(helper_dir: Path) -> None:
    helper = helper_dir / "cm_direct_client_v7.py"
    template = helper_dir / "200_sessions" / "cmd_0511_template.bin"
    missing = [str(p) for p in (helper, template) if not p.exists()]
    if missing:
        raise SystemExit("missing required helper files:\n  " + "\n  ".join(missing))


def cts_unswap(ct: bytes) -> bytes:
    if len(ct) < 32 or len(ct) % 16 != 0:
        return ct
    return ct[:-32] + ct[-16:] + ct[-32:-16]


def recv_response(v7, sock: socket.socket) -> dict[str, Any]:
    try:
        n, data, hdr = v7.recv_samc(sock)
    except socket.timeout:
        return {"status": "timeout", "samc_len": None, "wire_len": 0}
    except ConnectionError as exc:
        return {"status": "closed", "error": str(exc), "samc_len": None, "wire_len": 0}
    except OSError as exc:
        return {"status": "socket_error", "error": repr(exc), "samc_len": None, "wire_len": 0}
    if n is None:
        return {
            "status": "bad_header",
            "samc_len": None,
            "wire_len": len(data),
            "raw_header_hex": hdr.hex(),
        }
    return {
        "status": "response",
        "samc_len": n,
        "wire_len": len(data),
        "data_head_hex": data[:64].hex(),
    }


def do_ecdh(v7, sock: socket.socket) -> tuple[bytes, bytes]:
    privkey = v7.ec.generate_private_key(v7.ec.SECP224R1(), v7.default_backend())
    pub = privkey.public_key().public_numbers()
    our_point = b"\x04" + pub.x.to_bytes(28, "big") + pub.y.to_bytes(28, "big")
    v7.send_samc(sock, 0x3B)
    sock.sendall(b"\xA2\x05" + our_point)
    _, resp, _ = v7.recv_samc(sock)
    if len(resp) < 65:
        raise ConnectionError(f"short ECDH response: {len(resp)} bytes")
    sx = int.from_bytes(resp[9:37], "big")
    sy = int.from_bytes(resp[37:65], "big")
    server_pub = v7.ec.EllipticCurvePublicNumbers(
        sx, sy, v7.ec.SECP224R1()
    ).public_key(v7.default_backend())
    shared = privkey.exchange(v7.ec.ECDH(), server_pub)
    return v7.derive_key_iv(shared)


def send_cts_record(v7, sock: socket.socket, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    wire = v7.cts_encrypt(key, iv, plaintext)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    return wire


def build_query0031_plaintext(
    token: bytes,
    *,
    msg_type: int,
    qtype: int,
    size: int,
    struct_len: int,
    pad16: bytes | None = None,
    struct_pad8: bytes | None = None,
    corrupt_crc: bool = False,
) -> bytes:
    if len(token) != 4:
        raise ValueError("token must be 4 bytes")
    pad16 = b"\x00" * 16 if pad16 is None else pad16
    struct_pad8 = b"\x00" * 8 if struct_pad8 is None else struct_pad8
    if len(pad16) != 16:
        raise ValueError("pad16 must be 16 bytes")
    if len(struct_pad8) != 8:
        raise ValueError("struct_pad8 must be 8 bytes")
    header = struct.pack("<I", msg_type & 0xFFFFFFFF) + token
    header += struct.pack("<II", qtype & 0xFFFFFFFF, size & 0xFFFFFFFF)
    prefix = header + pad16 + struct_pad8 + struct.pack("<I", struct_len & 0xFFFFFFFF)
    crc = zlib.crc32(prefix) & 0xFFFFFFFF
    if corrupt_crc:
        crc ^= 1 << ((qtype ^ size ^ msg_type) & 31)
    struct_blk = struct_pad8 + struct.pack("<I", struct_len & 0xFFFFFFFF)
    struct_blk += struct.pack("<I", crc)
    plaintext = header + pad16 + struct_blk
    if len(plaintext) != 48:
        raise AssertionError(len(plaintext))
    return plaintext


def encrypt_query0031(v7, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(plaintext) != 48:
        raise ValueError("cmd=0x0031 query plaintext must be 48 bytes")
    first_two = v7.aes_cbc_enc(key, iv, plaintext[:32])
    c0, c1 = first_two[:16], first_two[16:32]
    struct_blk = plaintext[32:48]
    mac_in = bytes(a ^ b for a, b in zip(c1, struct_blk))
    mac = v7.aes_ecb_enc(key, mac_in)
    return c0 + mac + c1


def do_fixed_auth(v7, sock: socket.socket, key: bytes, iv: bytes) -> dict[str, Any]:
    send_cts_record(v7, sock, key, iv, v7.CMD_0021_AUTH_RECORD)
    return recv_response(v7, sock)


def do_init_0511(
    v7,
    sock: socket.socket,
    key: bytes,
    iv: bytes,
    *,
    firm: int | None,
    product: int | None,
    rng: random.Random,
) -> tuple[bytes, dict[str, Any]]:
    cm_uid = rng.getrandbits(32).to_bytes(4, "little")
    prev_uid = rng.getrandbits(32).to_bytes(4, "little")
    wire = v7.build_cmd_0511(key, iv, cm_uid, prev_uid, firm=firm, product=product)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    try:
        n, ack, _ = v7.recv_samc(sock)
    except socket.timeout:
        return b"\x00" * 4, {
            "status": "timeout",
            "cm_uid": cm_uid.hex(),
            "prev_uid": prev_uid.hex(),
        }
    except Exception as exc:
        return b"\x00" * 4, {
            "status": "error",
            "error": repr(exc),
            "cm_uid": cm_uid.hex(),
            "prev_uid": prev_uid.hex(),
        }

    token = b"\x00" * 4
    pt_head = b""
    if len(ack) >= 32 and len(ack) % 16 == 0:
        pt = v7.aes_cbc_dec(key, iv, cts_unswap(ack))
        pt_head = pt[:64]
        if len(pt) >= 8:
            token = pt[4:8]
    return token, {
        "status": "response",
        "samc_len": n,
        "wire_len": len(ack),
        "cm_uid": cm_uid.hex(),
        "prev_uid": prev_uid.hex(),
        "token_hex": token.hex(),
        "ack_plain_head_hex": pt_head.hex(),
        "ack_wire_head_hex": ack[:64].hex(),
    }


def choose_from(rng: random.Random, values: list[int], *, random_bits: int = 32) -> int:
    if rng.randrange(5) == 0:
        return rng.getrandbits(random_bits)
    return rng.choice(values)


def random_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


def choose_query_mutation(rng: random.Random, token: bytes) -> tuple[bytes, dict[str, Any]]:
    strategy_roll = rng.randrange(100)
    msg_type = 0x21
    qtype = choose_from(rng, INTERESTING_QTYPES)
    size = choose_from(rng, INTERESTING_SIZES)
    struct_len = 0x10
    pad16 = b"\x00" * 16
    struct_pad8 = b"\x00" * 8
    corrupt_crc = False
    strategy = "query_fields"

    if strategy_roll < 22:
        msg_type = 0x5E
        qtype = choose_from(rng, INTERESTING_QTYPES)
        size = choose_from(rng, INTERESTING_SIZES)
        strategy = "query_msg_type_5e"
    elif strategy_roll < 38:
        msg_type = choose_from(rng, INTERESTING_TYPES, random_bits=8) & 0xFF
        strategy = "query_msg_type_dictionary"
    elif strategy_roll < 55:
        struct_len = choose_from(rng, INTERESTING_LENGTHS)
        strategy = "query_struct_len"
    elif strategy_roll < 70:
        pad16 = random_bytes(rng, 16)
        strategy = "query_padding_noise"
    elif strategy_roll < 82:
        struct_pad8 = random_bytes(rng, 8)
        strategy = "query_struct_padding_noise"
    elif strategy_roll < 92:
        corrupt_crc = True
        strategy = "query_bad_crc"
    else:
        msg_type = rng.getrandbits(32)
        qtype = rng.getrandbits(32)
        size = rng.getrandbits(32)
        struct_len = rng.getrandbits(32)
        corrupt_crc = bool(rng.randrange(2))
        strategy = "query_random_header"

    plaintext = build_query0031_plaintext(
        token,
        msg_type=msg_type,
        qtype=qtype,
        size=size,
        struct_len=struct_len,
        pad16=pad16,
        struct_pad8=struct_pad8,
        corrupt_crc=corrupt_crc,
    )
    meta = {
        "strategy": strategy,
        "msg_type": msg_type & 0xFFFFFFFF,
        "qtype": qtype & 0xFFFFFFFF,
        "size": size & 0xFFFFFFFF,
        "struct_len": struct_len & 0xFFFFFFFF,
        "corrupt_crc": corrupt_crc,
        "pad16_hex": pad16.hex(),
        "struct_pad8_hex": struct_pad8.hex(),
    }
    return plaintext, meta


def choose_auth_mutation(v7, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    record = bytearray(v7.CMD_0021_AUTH_RECORD)
    roll = rng.randrange(100)
    strategy = "auth_field"
    recompute_crc = True

    if roll < 30:
        record[0:4] = struct.pack("<I", 0x5E)
        record[4:8] = struct.pack("<I", choose_from(rng, INTERESTING_TYPES, random_bits=8))
        strategy = "auth_type_5e"
    elif roll < 48:
        record[0:4] = struct.pack("<I", choose_from(rng, INTERESTING_TYPES, random_bits=8))
        strategy = "auth_type_dictionary"
    elif roll < 63:
        record[4:8] = struct.pack("<I", choose_from(rng, INTERESTING_QTYPES))
        strategy = "auth_field1"
    elif roll < 78:
        record[8:24] = random_bytes(rng, 16)
        strategy = "auth_middle_noise"
    elif roll < 90:
        record[24:28] = struct.pack("<I", choose_from(rng, INTERESTING_SIZES))
        strategy = "auth_size_field"
    else:
        record[0:28] = random_bytes(rng, 28)
        strategy = "auth_random_prefix"

    if rng.randrange(12) == 0:
        recompute_crc = False
    if recompute_crc:
        record[28:32] = struct.pack("<I", zlib.crc32(bytes(record[:28])) & 0xFFFFFFFF)
    else:
        old = struct.unpack("<I", record[28:32])[0]
        record[28:32] = struct.pack("<I", old ^ (1 << rng.randrange(32)))

    meta = {
        "strategy": strategy,
        "recompute_crc": recompute_crc,
        "msg_type": struct.unpack("<I", record[0:4])[0],
        "field1": struct.unpack("<I", record[4:8])[0],
        "size_field": struct.unpack("<I", record[24:28])[0],
    }
    return bytes(record), meta


def send_query_target(
    v7,
    sock: socket.socket,
    key: bytes,
    iv: bytes,
    token: bytes,
    rng: random.Random,
) -> tuple[dict[str, Any], bytes, bytes]:
    plaintext, mutation = choose_query_mutation(rng, token)
    wire = encrypt_query0031(v7, key, iv, plaintext)
    v7.send_samc(sock, 1 + len(wire))
    sock.sendall(b"\xA1" + wire)
    response = recv_response(v7, sock)
    return {
        "target": "query0031",
        "mutation": mutation,
        "response": response,
    }, plaintext, wire


def send_auth_target(
    v7,
    sock: socket.socket,
    key: bytes,
    iv: bytes,
    rng: random.Random,
) -> tuple[dict[str, Any], bytes, bytes]:
    plaintext, mutation = choose_auth_mutation(v7, rng)
    wire = send_cts_record(v7, sock, key, iv, plaintext)
    response = recv_response(v7, sock)
    return {
        "target": "auth0021",
        "mutation": mutation,
        "response": response,
    }, plaintext, wire


def run_attempt(
    v7,
    *,
    worker_id: int,
    iteration: int,
    target_host: str,
    target_port: int,
    connect_timeout: float,
    socket_timeout: float,
    mode: str,
    firm: int | None,
    product: int | None,
    rng: random.Random,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    start = time.time()
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "started_at": start,
        "mode": mode,
        "target_host": target_host,
        "target_port": target_port,
        "sent_target": False,
    }
    frames: list[tuple[str, bytes]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connect_timeout)
    try:
        sock.connect((target_host, target_port))
        sock.settimeout(socket_timeout)
        key, iv = do_ecdh(v7, sock)
        attempt["ecdh"] = "ok"

        chosen_mode = mode
        if mode == "mixed":
            chosen_mode = "query0031" if rng.randrange(100) < 80 else "auth0021"
        attempt["chosen_mode"] = chosen_mode

        if chosen_mode == "auth0021":
            meta, plaintext, _wire = send_auth_target(v7, sock, key, iv, rng)
            frames.append(("target_auth0021_plaintext.bin", plaintext))
            attempt.update(meta)
            attempt["sent_target"] = True
            return attempt, frames

        if chosen_mode != "query0031":
            raise ValueError(f"unknown mode: {chosen_mode}")

        auth_ack = do_fixed_auth(v7, sock, key, iv)
        token, init_meta = do_init_0511(
            v7, sock, key, iv, firm=firm, product=product, rng=rng,
        )
        attempt["auth_ack"] = auth_ack
        attempt["init_0511"] = init_meta
        attempt["session_token_hex"] = token.hex()

        meta, plaintext, _wire = send_query_target(v7, sock, key, iv, token, rng)
        frames.append(("target_query0031_plaintext.bin", plaintext))
        attempt.update(meta)
        attempt["sent_target"] = True
        return attempt, frames
    except socket.timeout as exc:
        attempt["error"] = {"stage": "timeout", "detail": str(exc)}
        return attempt, frames
    except Exception as exc:
        attempt["error"] = {
            "stage": "exception",
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }
        return attempt, frames
    finally:
        attempt["finished_at"] = time.time()
        attempt["duration_s"] = attempt["finished_at"] - start
        try:
            sock.close()
        except OSError:
            pass


def summarize_attempt(attempt: dict[str, Any]) -> str:
    if "error" in attempt:
        return f"error:{attempt['error'].get('stage')}"
    response = attempt.get("response") or {}
    return str(response.get("status", "unknown"))


def dump_worker_ring(
    worker_dir: Path,
    ring: collections.deque,
    stats: dict[str, Any],
    reason: str,
) -> None:
    worker_dir.mkdir(parents=True, exist_ok=True)
    json_dump(worker_dir / "worker_summary.json", {
        "reason": reason,
        "stats": stats,
        "ring_count": len(ring),
        "dumped_at": time.time(),
    })
    manifest_path = worker_dir / "ring_manifest.jsonl"
    with manifest_path.open("w", encoding="utf-8") as manifest:
        for idx, item in enumerate(ring):
            attempt = dict(item["attempt"])
            frames = item["frames"]
            iter_dir = worker_dir / "ring" / f"idx_{idx:04d}_iter_{attempt['iteration']:08d}"
            iter_dir.mkdir(parents=True, exist_ok=True)
            frame_meta = []
            for frame_name, data in frames:
                frame_path = iter_dir / frame_name
                frame_path.write_bytes(data)
                frame_meta.append({
                    "name": frame_name,
                    "path": str(frame_path),
                    "len": len(data),
                    "head_hex": data[:64].hex(),
                })
            attempt["frames"] = frame_meta
            json_dump(iter_dir / "attempt.json", attempt)
            manifest.write(json.dumps({
                "idx": idx,
                "iteration": attempt["iteration"],
                "target": attempt.get("target"),
                "strategy": (attempt.get("mutation") or {}).get("strategy"),
                "status": summarize_attempt(attempt),
                "attempt_json": str(iter_dir / "attempt.json"),
            }, sort_keys=True) + "\n")


def worker_main(
    worker_id: int,
    args_dict: dict[str, Any],
    stop_event,
    result_q,
) -> None:
    out_dir = Path(args_dict["out_dir"])
    worker_dir = out_dir / f"worker_{worker_id:02d}"
    seed = int(args_dict["seed_base"]) + worker_id * 0x1000003
    rng = random.Random(seed)
    ring: collections.deque = collections.deque(maxlen=int(args_dict["ring_size"]))
    stats: dict[str, Any] = {
        "worker_id": worker_id,
        "seed": seed,
        "attempts": 0,
        "sent_targets": 0,
        "statuses": {},
        "started_at": time.time(),
    }

    try:
        v7 = load_v7(Path(args_dict["helper_dir"]))
        for iteration in range(int(args_dict["iterations"])):
            if stop_event.is_set():
                break
            attempt, frames = run_attempt(
                v7,
                worker_id=worker_id,
                iteration=iteration,
                target_host=args_dict["target_host"],
                target_port=int(args_dict["target_port"]),
                connect_timeout=float(args_dict["connect_timeout"]),
                socket_timeout=float(args_dict["socket_timeout"]),
                mode=args_dict["mode"],
                firm=args_dict["firm"],
                product=args_dict["product"],
                rng=rng,
            )
            stats["attempts"] += 1
            status = summarize_attempt(attempt)
            stats["statuses"][status] = stats["statuses"].get(status, 0) + 1
            if attempt.get("sent_target"):
                stats["sent_targets"] += 1
                ring.append({"attempt": attempt, "frames": frames})
            if stats["attempts"] % int(args_dict["worker_progress_every"]) == 0:
                result_q.put({
                    "event": "worker_progress",
                    "worker_id": worker_id,
                    "attempts": stats["attempts"],
                    "sent_targets": stats["sent_targets"],
                    "statuses": dict(stats["statuses"]),
                    "time": time.time(),
                })
    except Exception as exc:
        stats["fatal_error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(),
        }
        result_q.put({
            "event": "worker_error",
            "worker_id": worker_id,
            "error": stats["fatal_error"],
            "time": time.time(),
        })
    finally:
        stats["finished_at"] = time.time()
        stats["duration_s"] = stats["finished_at"] - stats["started_at"]
        reason = "stop_event" if stop_event.is_set() else "completed"
        if "fatal_error" in stats:
            reason = "worker_error"
        dump_worker_ring(worker_dir, ring, stats, reason)
        result_q.put({
            "event": "worker_done",
            "worker_id": worker_id,
            "reason": reason,
            "attempts": stats["attempts"],
            "sent_targets": stats["sent_targets"],
            "statuses": dict(stats["statuses"]),
            "time": time.time(),
        })


def start_pipe_logger(name: str, pipe, log_path: Path, event_q: queue.Queue | None = None) -> threading.Thread:
    def run() -> None:
        with log_path.open("a", encoding="utf-8") as log:
            for line in pipe:
                log.write(line)
                log.flush()
                if event_q is None:
                    continue
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event_q.put(json.loads(stripped))
                except json.JSONDecodeError:
                    event_q.put({"event": "monitor_text", "stream": name, "line": stripped})

    t = threading.Thread(target=run, name=f"{name}-logger", daemon=True)
    t.start()
    return t


def start_remote_monitor(args, out_dir: Path) -> tuple[subprocess.Popen, queue.Queue]:
    event_q: queue.Queue = queue.Queue()
    core_dirs = args.core_dir or ["/var/tmp/cm_cores", "/var/lib/systemd/coredump"]
    script = (
        f"INTERVAL = {float(args.monitor_interval)!r}\n"
        f"CORE_DIRS = {core_dirs!r}\n"
        + REMOTE_MONITOR_BODY
    )

    remote_cmd = "python3 -u -"
    if args.monitor_sudo:
        remote_cmd = "sudo -n python3 -u -"
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(args.ssh_timeout)}",
        "-o", "StrictHostKeyChecking=accept-new",
    ]
    for opt in args.ssh_option:
        cmd.extend(["-o", opt])
    cmd.extend([args.ssh_host, remote_cmd])

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None
    proc.stdin.write(script)
    proc.stdin.close()
    assert proc.stdout is not None
    assert proc.stderr is not None
    start_pipe_logger("monitor_stdout", proc.stdout, out_dir / "remote_monitor_stdout.log", event_q)
    start_pipe_logger("monitor_stderr", proc.stderr, out_dir / "remote_monitor_stderr.log", None)
    return proc, event_q


def wait_for_baseline(monitor_proc: subprocess.Popen, event_q: queue.Queue, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            event = event_q.get(timeout=0.2)
        except queue.Empty:
            if monitor_proc.poll() is not None:
                raise RuntimeError(f"remote monitor exited before baseline: rc={monitor_proc.returncode}")
            continue
        if event.get("event") == "baseline":
            return event
        if event.get("event") == "monitor_text":
            continue
    raise TimeoutError("remote monitor did not report baseline")


def drain_mp_queue(result_q, max_items: int = 1000) -> list[dict[str, Any]]:
    events = []
    for _ in range(max_items):
        try:
            events.append(result_q.get_nowait())
        except queue.Empty:
            break
    return events


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Fuzz remote CodeMeter daemon-to-server records and monitor crashes over SSH."
    )
    ap.add_argument("--target-host", default="vistrrdslin0004.vi.vector.int")
    ap.add_argument("--target-port", type=int, default=22350)
    ap.add_argument("--ssh-host", default=None,
                    help="Host used for remote crash monitoring; defaults to --target-host.")
    ap.add_argument("--helper-dir", type=Path, default=DEFAULT_HELPER_DIR,
                    help="Directory containing cm_direct_client_v7.py and 200_sessions/ template.")
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--iterations", type=int, default=1000,
                    help="Iterations per worker.")
    ap.add_argument("--mode", choices=["query0031", "auth0021", "mixed"], default="query0031")
    ap.add_argument("--seed-base", type=lambda s: int(s, 0), default=0xC0DE5000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--worker-progress-every", type=int, default=250)
    ap.add_argument("--timeout", type=float, default=0.0,
                    help="Optional total runtime limit in seconds; 0 means no controller timeout.")
    ap.add_argument("--connect-timeout", type=float, default=2.0)
    ap.add_argument("--socket-timeout", type=float, default=2.0)
    ap.add_argument("--firm", type=int, default=None,
                    help="Optional firm code patched into the 0x0511 init template.")
    ap.add_argument("--product", type=int, default=None,
                    help="Optional product code patched into the 0x0511 init template.")
    ap.add_argument("--monitor-interval", type=float, default=0.25)
    ap.add_argument("--ssh-timeout", type=float, default=8.0)
    ap.add_argument("--ssh-option", action="append", default=[],
                    help="Extra ssh -o option, e.g. 'ProxyJump=host'. May be repeated.")
    ap.add_argument("--monitor-sudo", action="store_true",
                    help="Run the remote monitor as sudo -n python3 for restricted core dirs.")
    ap.add_argument("--core-dir", action="append", default=[],
                    help="Remote core directory to watch. Defaults to /var/tmp/cm_cores and systemd-coredump.")
    ap.add_argument("--no-monitor", action="store_true",
                    help="Disable SSH crash monitor; useful only for plumbing tests.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Validate inputs and write run_config.json without sending traffic.")
    return ap


def args_to_config(args) -> dict[str, Any]:
    cfg = vars(args).copy()
    for key in ("helper_dir", "out_dir"):
        if cfg.get(key) is not None:
            cfg[key] = str(cfg[key])
    return cfg


def stop_process(proc: subprocess.Popen | None, grace: float = 5.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass


def run_controller(args) -> int:
    if args.ssh_host is None:
        args.ssh_host = args.target_host
    if args.out_dir is None:
        args.out_dir = REPO_ROOT / "output" / f"remote_cm_fuzz_{now_slug()}"
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    validate_helper_dir(args.helper_dir)
    json_dump(out_dir / "run_config.json", args_to_config(args))
    print(f"[+] out_dir={out_dir}")
    print(f"[+] target={args.target_host}:{args.target_port} mode={args.mode} workers={args.workers}")

    if args.dry_run:
        print("[+] dry-run complete; no traffic sent")
        return 0

    monitor_proc: subprocess.Popen | None = None
    monitor_q: queue.Queue | None = None
    baseline: dict[str, Any] | None = None
    if not args.no_monitor:
        print(f"[+] starting remote monitor on {args.ssh_host}")
        monitor_proc, monitor_q = start_remote_monitor(args, out_dir)
        baseline = wait_for_baseline(monitor_proc, monitor_q, args.ssh_timeout + 10.0)
        pid_key = baseline.get("state", {}).get("daemon", {}).get("pid_key")
        core_key = baseline.get("state", {}).get("cores", {}).get("key")
        print(f"[+] monitor baseline pid_key={pid_key} core_key={core_key}")
    else:
        print("[!] remote monitor disabled; crash attribution will be manual")

    mp_ctx = mp.get_context("fork")
    stop_event = mp_ctx.Event()
    result_q = mp_ctx.Queue()
    worker_args = args_to_config(args)
    procs: list[mp.Process] = []
    for worker_id in range(args.workers):
        p = mp_ctx.Process(
            target=worker_main,
            args=(worker_id, worker_args, stop_event, result_q),
            name=f"remote-cm-worker-{worker_id:02d}",
        )
        p.start()
        procs.append(p)

    stop_reason = "completed"
    crash_event: dict[str, Any] | None = None
    worker_events: list[dict[str, Any]] = []
    started = time.monotonic()
    last_progress_print = 0.0

    try:
        while True:
            if monitor_q is not None:
                while True:
                    try:
                        event = monitor_q.get_nowait()
                    except queue.Empty:
                        break
                    if event.get("event") == "change":
                        crash_event = event
                        stop_reason = "remote_change"
                        print(f"[!] remote monitor change: {event.get('reasons')}")
                        stop_event.set()
                    elif event.get("event") not in ("baseline", "monitor_text"):
                        worker_events.append({"monitor_event": event})

            for event in drain_mp_queue(result_q):
                worker_events.append(event)
                if event.get("event") == "worker_error":
                    print(f"[!] worker {event.get('worker_id')} error: {event.get('error', {}).get('detail')}")
                elif event.get("event") == "worker_progress":
                    now = time.monotonic()
                    if now - last_progress_print > 10.0:
                        last_progress_print = now
                        print(
                            f"[+] progress w{event['worker_id']:02d}: "
                            f"attempts={event['attempts']} sent={event['sent_targets']}"
                        )

            if args.timeout and (time.monotonic() - started) >= args.timeout:
                stop_reason = "timeout"
                print("[!] controller timeout reached")
                stop_event.set()

            if all(p.exitcode is not None for p in procs):
                break
            if stop_event.is_set() and all(not p.is_alive() for p in procs):
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_reason = "keyboard_interrupt"
        stop_event.set()
    finally:
        if stop_event.is_set():
            for p in procs:
                p.join(timeout=max(args.socket_timeout + args.connect_timeout + 1.0, 5.0))
            for p in procs:
                if p.is_alive():
                    p.terminate()
            for p in procs:
                p.join(timeout=2.0)
        else:
            for p in procs:
                p.join()
        stop_process(monitor_proc)

    for event in drain_mp_queue(result_q):
        worker_events.append(event)

    summary = {
        "stop_reason": stop_reason,
        "crash_event": crash_event,
        "baseline": baseline,
        "worker_exitcodes": [p.exitcode for p in procs],
        "worker_events_tail": worker_events[-100:],
        "started_monotonic": started,
        "finished_at": time.time(),
        "out_dir": str(out_dir),
    }
    json_dump(out_dir / "summary.json", summary)
    print(f"[+] wrote {out_dir / 'summary.json'}")
    if crash_event is not None:
        print("[!] stopped after remote daemon/core change; inspect worker_*/ring artifacts")
    return 0


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    if args.ring_size < 1:
        raise SystemExit("--ring-size must be >= 1")
    if args.worker_progress_every < 1:
        raise SystemExit("--worker-progress-every must be >= 1")
    return run_controller(args)


if __name__ == "__main__":
    raise SystemExit(main())
