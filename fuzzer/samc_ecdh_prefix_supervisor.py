#!/usr/bin/env python3
"""ECDH-channel prefix/dispatcher fuzzer for CodeMeterLin SAMC messages.

This is purpose-built for the bug class exposed by the remote-capable
prefixed-HELLO reproducer:

  valid outer samc frame
  valid ECDH selector channel
  parser-visible plaintext = attacker prefix || mostly canonical message

The generic local supervisor mutates PSK-channel frames and relies on random
insertions.  This supervisor instead enumerates prefix lengths, leading opcode
bytes, and field-shift patterns while keeping the crypto, length, CRC, HELLO
token, and ACK SID handling valid.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import multiprocessing as mp
import os
from pathlib import Path
import random
import socket
import struct
import sys
import time
import traceback
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_REPRO = HERE / "repro_prefixed_hello_standalone.py"
DEFAULT_KNOWN_HELLO_PREFIX = "5e355ed6f2"

PREFIX_VARIANTS = [
    "zero_tail",
    "random_tail",
    "repeat_opcode",
    "second_5e",
    "counter_tail",
    "danger_u32_at_04",
    "danger_u32_at_08",
    "danger_u32_at_0c",
    "danger_u32_at_10",
    "dict_tail",
]

DANGER_U32 = [
    0x00000000,
    0x00000001,
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000028,
    0x00000040,
    0x00000080,
    0x00000100,
    0x00001000,
    0x28000010,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
]

DICT_TAILS = [
    bytes.fromhex("35"),
    bytes.fromhex("5e"),
    bytes.fromhex("5ed6f2"),
    bytes.fromhex("355ed6f2"),
    b"\x00\x00\x00",
    b"\x10\x00\x00\x28",
    b"\x28\x00\x00\x00",
    b"\xff\xff\xff\xff",
]

FIELD_OFFSETS = [0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18]


def json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_int_spec(spec: str, *, mask: int | None = None) -> list[int]:
    """Parse comma-separated ints/ranges like '0x00-0xff,0x5e'."""
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo = int(lo_s.strip(), 0)
            hi = int(hi_s.strip(), 0)
            if lo > hi:
                lo, hi = hi, lo
            values.update(range(lo, hi + 1))
        else:
            values.add(int(part, 0))
    out = sorted(values)
    if mask is not None:
        out = sorted({v & mask for v in out})
    return out


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_repro(path: Path):
    return load_module(path, "repro_prefixed_hello_standalone_for_prefix_fuzz")


def load_samc(ax_fuzz: Path):
    mod_path = ax_fuzz / "tier1" / "samc_fuzz.py"
    sys.path.insert(0, str(mod_path.parent))
    return load_module(mod_path, "samc_fuzz_for_ecdh_prefix")


def recv_response_meta(repro, sock: socket.socket, key: bytes, iv: bytes,
                       timeout: float) -> tuple[dict[str, Any], bytes | None]:
    try:
        payload = repro.recv_samc_payload(sock, timeout)
    except socket.timeout:
        return {"status": "timeout", "payload_len": None}, None
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        return {
            "status": "recv_exception",
            "exception": f"{type(exc).__name__}:{exc}",
            "payload_len": None,
        }, None

    if payload is None:
        return {"status": "none", "payload_len": None}, None

    inner = repro.decrypt_ecdh_response(payload, key, iv)
    meta: dict[str, Any] = {
        "status": "payload",
        "payload_len": len(payload),
        "inner_len": None if inner is None else len(inner),
        "payload_head_hex": payload[:64].hex(),
    }
    if inner is not None:
        meta["inner_head_hex"] = inner[:64].hex()
        if len(inner) >= 8:
            meta["sid_hex"] = inner[4:8].hex()
    return meta, inner


def listener_ready(host: str, port: int, timeout: float = 0.4) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def newest_core(core_dirs: list[Path]) -> dict[str, Any] | None:
    newest: tuple[int, Path] | None = None
    for root in core_dirs:
        if not root.exists():
            continue
        for path in root.glob("*CodeMeterLin*"):
            try:
                st = path.stat()
            except OSError:
                continue
            item = (st.st_mtime_ns, path)
            if newest is None or item > newest:
                newest = item
    if newest is None:
        return None
    st = newest[1].stat()
    return {"path": str(newest[1]), "mtime_ns": st.st_mtime_ns, "size": st.st_size}


def core_changed_since(
    baseline_core: dict[str, Any] | None,
    current_core: dict[str, Any] | None,
    start_wall: float,
) -> bool:
    return (
        current_core is not None and
        (baseline_core is None or
         current_core["path"] != baseline_core["path"] or
         current_core["mtime_ns"] != baseline_core["mtime_ns"]) and
        current_core["mtime_ns"] >= int(start_wall * 1_000_000_000)
    )


def u32_at(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def repeat_to_len(data: bytes, length: int) -> bytes:
    if length <= 0:
        return b""
    if not data:
        data = b"\x00"
    return (data * ((length + len(data) - 1) // len(data)))[:length]


def overlay_u32(prefix: bytearray, offset: int, value: int) -> bool:
    raw = struct.pack("<I", value & 0xFFFFFFFF)
    if offset < 0 or offset + 4 > len(prefix):
        return False
    prefix[offset:offset + 4] = raw
    return True


def build_prefix(
    *,
    global_index: int,
    rng: random.Random,
    opcodes: list[int],
    prefix_lengths: list[int],
    known_prefix: bytes,
    include_known_every: int,
) -> tuple[bytes, dict[str, Any]]:
    """Build one parser-visible prefix and enough metadata to replay it."""
    if include_known_every and global_index % include_known_every == 0:
        return known_prefix, {
            "strategy": "known_prefixed_hello",
            "global_index": global_index,
            "opcode": known_prefix[0],
            "prefix_len": len(known_prefix),
        }

    idx = global_index
    opcode = opcodes[idx % len(opcodes)]
    idx //= len(opcodes)
    prefix_len = prefix_lengths[idx % len(prefix_lengths)]
    idx //= len(prefix_lengths)
    variant = PREFIX_VARIANTS[idx % len(PREFIX_VARIANTS)]
    idx //= len(PREFIX_VARIANTS)
    danger = DANGER_U32[idx % len(DANGER_U32)]
    idx //= len(DANGER_U32)
    dict_tail = DICT_TAILS[idx % len(DICT_TAILS)]

    prefix = bytearray(prefix_len)
    if prefix_len:
        prefix[0] = opcode & 0xFF

    if variant == "zero_tail":
        pass
    elif variant == "random_tail":
        for pos in range(1, prefix_len):
            prefix[pos] = rng.randrange(256)
    elif variant == "repeat_opcode":
        for pos in range(prefix_len):
            prefix[pos] = opcode & 0xFF
    elif variant == "second_5e":
        for pos in range(1, prefix_len):
            prefix[pos] = rng.randrange(256)
        if prefix_len > 2:
            prefix[2] = 0x5E
    elif variant == "counter_tail":
        for pos in range(1, prefix_len):
            prefix[pos] = (global_index + pos) & 0xFF
    elif variant.startswith("danger_u32_at_"):
        for pos in range(1, prefix_len):
            prefix[pos] = rng.randrange(256)
        field_off = int(variant.rsplit("_", 1)[1], 16)
        overlay_u32(prefix, field_off, danger)
    elif variant == "dict_tail":
        tail = repeat_to_len(dict_tail, max(prefix_len - 1, 0))
        prefix[1:] = tail
    else:
        raise AssertionError(variant)

    meta = {
        "strategy": variant,
        "global_index": global_index,
        "opcode": opcode,
        "prefix_len": prefix_len,
        "danger_u32": danger,
        "dict_tail_hex": dict_tail.hex(),
    }
    return bytes(prefix), meta


def message_words(prefix: bytes, canonical: bytes) -> dict[str, str | None]:
    data = prefix + canonical
    out: dict[str, str | None] = {}
    for off in FIELD_OFFSETS:
        value = u32_at(data, off)
        out[f"u32_0x{off:02x}"] = None if value is None else f"0x{value:08x}"
    return out


def send_ecdh_plaintext(repro, sock: socket.socket, key: bytes, iv: bytes,
                        plaintext: bytes) -> None:
    payload = repro.encrypt_ecdh_payload(plaintext, key, iv)
    repro.send_samc_payload(sock, payload)


def run_one_hello(
    repro,
    *,
    host: str,
    port: int,
    connect_timeout: float,
    socket_timeout: float,
    prefix: bytes,
    prefix_meta: dict[str, Any],
    worker_id: int,
    iteration: int,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    canonical, token = repro.fresh_hello()
    mutated = prefix + canonical
    repro.validate_default_crash_layout(prefix, mutated)
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "target": "hello",
        "prefix": prefix_meta,
        "prefix_hex": prefix.hex(),
        "canonical_len": len(canonical),
        "target_len": len(mutated),
        "token_hex": token.hex(),
        "field_words": message_words(prefix, canonical),
        "wall_start": time.time(),
        "mono_start_ns": time.monotonic_ns(),
        "sent_target": False,
    }
    frames = [
        ("prefix.bin", prefix),
        ("canonical_hello.bin", canonical),
        ("target_hello_plaintext.bin", mutated),
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        sock.connect((host, port))
        sock.settimeout(socket_timeout)
        key, iv, ecdh_response = repro.do_ecdh_handshake(sock, socket_timeout)
        attempt["ecdh_response_head_hex"] = ecdh_response[:65].hex()
        frame_meta = {
            "idx": 0,
            "name": "target_hello",
            "send_start_mono_ns": time.monotonic_ns(),
            "plaintext_len": len(mutated),
        }
        send_ecdh_plaintext(repro, sock, key, iv, mutated)
        frame_meta["send_end_mono_ns"] = time.monotonic_ns()
        attempt["sent_target"] = True
        response, inner = recv_response_meta(repro, sock, key, iv, socket_timeout)
        frame_meta["response"] = response
        attempt["frames"] = [frame_meta]
        if response["status"] in {"none", "timeout", "recv_exception"}:
            attempt["status"] = "target_no_response"
        elif inner is None:
            attempt["status"] = "target_decrypt_fail"
        else:
            attempt["status"] = "ok"
        return attempt, frames
    except Exception as exc:
        attempt["status"] = "exception"
        attempt["error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }
        return attempt, frames
    finally:
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        try:
            sock.close()
        except OSError:
            pass


def run_one_ack(
    repro,
    samc,
    *,
    host: str,
    port: int,
    connect_timeout: float,
    socket_timeout: float,
    prefix: bytes,
    prefix_meta: dict[str, Any],
    worker_id: int,
    iteration: int,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    hello, token = repro.fresh_hello()
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "target": "ack",
        "prefix": prefix_meta,
        "prefix_hex": prefix.hex(),
        "token_hex": token.hex(),
        "wall_start": time.time(),
        "mono_start_ns": time.monotonic_ns(),
        "sent_target": False,
    }
    frames: list[tuple[str, bytes]] = [
        ("prefix.bin", prefix),
        ("canonical_hello.bin", hello),
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(connect_timeout)
        sock.connect((host, port))
        sock.settimeout(socket_timeout)
        key, iv, ecdh_response = repro.do_ecdh_handshake(sock, socket_timeout)
        attempt["ecdh_response_head_hex"] = ecdh_response[:65].hex()

        hello_frame = {
            "idx": 0,
            "name": "canonical_hello",
            "send_start_mono_ns": time.monotonic_ns(),
            "plaintext_len": len(hello),
        }
        send_ecdh_plaintext(repro, sock, key, iv, hello)
        hello_frame["send_end_mono_ns"] = time.monotonic_ns()
        hello_response, hello_inner = recv_response_meta(repro, sock, key, iv, socket_timeout)
        hello_frame["response"] = hello_response
        attempt["frames"] = [hello_frame]
        if hello_inner is None or len(hello_inner) < 8:
            attempt["status"] = "hello_no_session"
            return attempt, frames

        sid = hello_inner[4:8]
        attempt["sid_hex"] = sid.hex()
        canonical_ack = samc.apply_sid_patches(1, samc.CAPTURED_SESSION_C2D[1], [sid])
        mutated_ack = prefix + canonical_ack
        attempt["canonical_len"] = len(canonical_ack)
        attempt["target_len"] = len(mutated_ack)
        attempt["field_words"] = message_words(prefix, canonical_ack)
        frames.extend([
            ("canonical_ack.bin", canonical_ack),
            ("target_ack_plaintext.bin", mutated_ack),
        ])

        ack_frame = {
            "idx": 1,
            "name": "target_ack",
            "send_start_mono_ns": time.monotonic_ns(),
            "plaintext_len": len(mutated_ack),
        }
        send_ecdh_plaintext(repro, sock, key, iv, mutated_ack)
        ack_frame["send_end_mono_ns"] = time.monotonic_ns()
        attempt["sent_target"] = True
        ack_response, ack_inner = recv_response_meta(repro, sock, key, iv, socket_timeout)
        ack_frame["response"] = ack_response
        attempt["frames"].append(ack_frame)
        if ack_response["status"] in {"none", "timeout", "recv_exception"}:
            attempt["status"] = "target_no_response"
        elif ack_inner is None:
            attempt["status"] = "target_decrypt_fail"
        else:
            attempt["status"] = "ok"
        return attempt, frames
    except Exception as exc:
        attempt["status"] = "exception"
        attempt["error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }
        return attempt, frames
    finally:
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        try:
            sock.close()
        except OSError:
            pass


def status_for(attempt: dict[str, Any]) -> str:
    return str(attempt.get("status", "unknown"))


def dump_ring(worker_dir: Path, ring: collections.deque, stats: dict[str, Any],
              reason: str) -> None:
    worker_dir.mkdir(parents=True, exist_ok=True)
    manifest = worker_dir / "ring_manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as mf:
        for idx, item in enumerate(ring):
            attempt = dict(item["attempt"])
            iter_dir = worker_dir / "ring" / f"idx_{idx:04d}_iter_{attempt['iteration']:08d}"
            iter_dir.mkdir(parents=True, exist_ok=True)
            file_meta = []
            for name, data in item["files"]:
                path = iter_dir / name
                path.write_bytes(data)
                file_meta.append({
                    "name": name,
                    "path": str(path),
                    "len": len(data),
                    "sha256": sha256_hex(data),
                    "head_hex": data[:64].hex(),
                })
            attempt["files"] = file_meta
            json_write(iter_dir / "attempt.json", attempt)
            mf.write(json.dumps({
                "idx": idx,
                "iteration": attempt["iteration"],
                "target": attempt.get("target"),
                "status": attempt.get("status"),
                "prefix": attempt.get("prefix"),
                "target_len": attempt.get("target_len"),
                "attempt_json": str(iter_dir / "attempt.json"),
            }, sort_keys=True) + "\n")
    json_write(worker_dir / "worker_summary.json", {
        "reason": reason,
        "stats": stats,
        "ring_count": len(ring),
        "dumped_at": time.time(),
    })


def worker_main(worker_id: int, args_dict: dict[str, Any], stop_event, counter) -> None:
    out_dir = Path(args_dict["out_dir"])
    worker_dir = out_dir / f"worker_{worker_id:02d}"
    rng = random.Random(int(args_dict["seed_base"]) + worker_id * 0x1000003)
    ring: collections.deque = collections.deque(maxlen=int(args_dict["ring_size"]))
    stats: dict[str, Any] = {
        "worker_id": worker_id,
        "attempts": 0,
        "sent_targets": 0,
        "statuses": {},
        "started_at": time.time(),
    }
    reason = "completed"

    try:
        repro = load_repro(Path(args_dict["repro"]))
        samc = None
        if args_dict["mode"] in {"ack", "mixed"}:
            samc = load_samc(Path(args_dict["ax_fuzz"]))
        opcodes = list(args_dict["opcodes"])
        prefix_lengths = list(args_dict["prefix_lengths"])
        known_prefix = bytes.fromhex(args_dict["known_prefix"])
        include_known_every = int(args_dict["include_known_every"])
        worker_count = int(args_dict["workers"])

        for iteration in range(int(args_dict["iterations"])):
            if stop_event.is_set():
                reason = "stop_event"
                break
            target = args_dict["mode"]
            if target == "mixed":
                target = "hello" if (iteration + worker_id) % 2 == 0 else "ack"
            global_index = worker_id + iteration * worker_count
            prefix, prefix_meta = build_prefix(
                global_index=global_index,
                rng=rng,
                opcodes=opcodes,
                prefix_lengths=prefix_lengths,
                known_prefix=known_prefix,
                include_known_every=include_known_every,
            )
            if target == "hello":
                attempt, files = run_one_hello(
                    repro,
                    host=args_dict["host"],
                    port=int(args_dict["port"]),
                    connect_timeout=float(args_dict["connect_timeout"]),
                    socket_timeout=float(args_dict["socket_timeout"]),
                    prefix=prefix,
                    prefix_meta=prefix_meta,
                    worker_id=worker_id,
                    iteration=iteration,
                )
            elif target == "ack":
                if samc is None:
                    raise AssertionError("ACK mode requires samc helper")
                attempt, files = run_one_ack(
                    repro,
                    samc,
                    host=args_dict["host"],
                    port=int(args_dict["port"]),
                    connect_timeout=float(args_dict["connect_timeout"]),
                    socket_timeout=float(args_dict["socket_timeout"]),
                    prefix=prefix,
                    prefix_meta=prefix_meta,
                    worker_id=worker_id,
                    iteration=iteration,
                )
            else:
                raise AssertionError(target)

            stats["attempts"] += 1
            counter.value = stats["attempts"]
            status = status_for(attempt)
            stats["statuses"][status] = stats["statuses"].get(status, 0) + 1
            if attempt.get("sent_target"):
                stats["sent_targets"] += 1
                ring.append({"attempt": attempt, "files": files})
    except Exception as exc:
        reason = "worker_error"
        stats["fatal_error"] = {
            "type": type(exc).__name__,
            "detail": str(exc),
            "traceback": traceback.format_exc(),
        }
    finally:
        stats["finished_at"] = time.time()
        stats["duration_s"] = stats["finished_at"] - stats["started_at"]
        dump_ring(worker_dir, ring, stats, reason)


def write_crash_attribution(out_dir: Path) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for worker_dir in sorted(out_dir.glob("worker_*")):
        manifest = worker_dir / "ring_manifest.jsonl"
        if not manifest.exists():
            continue
        for line in manifest.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("status") not in {"target_no_response", "exception"}:
                continue
            attempt_path = Path(entry["attempt_json"])
            try:
                attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            except Exception:
                attempt = {}
            target_frame = None
            for frame in attempt.get("frames", []):
                if str(frame.get("name", "")).startswith("target_"):
                    target_frame = frame
                    break
            events.append({
                "worker_id": attempt.get("worker_id", entry.get("worker_id")),
                "iteration": entry.get("iteration"),
                "target": entry.get("target"),
                "status": entry.get("status"),
                "prefix": entry.get("prefix"),
                "target_len": entry.get("target_len"),
                "send_start_mono_ns": None if target_frame is None else target_frame.get("send_start_mono_ns"),
                "send_end_mono_ns": None if target_frame is None else target_frame.get("send_end_mono_ns"),
                "attempt_json": str(attempt_path),
            })
    events.sort(key=lambda e: (e["send_start_mono_ns"] is None, e["send_start_mono_ns"] or 0))
    report = {"count": len(events), "events": events}
    json_write(out_dir / "crash_attribution.json", report)
    return report


def run_supervisor(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    opcodes = parse_int_spec(args.opcodes, mask=0xFF)
    skip = set(parse_int_spec(args.skip_opcodes, mask=0xFF)) if args.skip_opcodes else set()
    opcodes = [op for op in opcodes if op not in skip]
    prefix_lengths = parse_int_spec(args.prefix_lengths)
    prefix_lengths = [n for n in prefix_lengths if n > 0]
    if not opcodes:
        raise SystemExit("--opcodes/--skip-opcodes resolved to an empty set")
    if not prefix_lengths:
        raise SystemExit("--prefix-lengths resolved to an empty set")

    core_dirs = [Path(p) for p in args.core_dir]
    baseline_core = newest_core(core_dirs)
    start_wall = time.time()
    start_mono = time.monotonic()
    config = {
        "host": args.host,
        "port": args.port,
        "out_dir": str(out_dir),
        "mode": args.mode,
        "workers": args.workers,
        "iterations": args.iterations,
        "ring_size": args.ring_size,
        "seed_base": args.seed_base,
        "connect_timeout": args.connect_timeout,
        "socket_timeout": args.socket_timeout,
        "opcodes": opcodes,
        "skip_opcodes": sorted(skip),
        "prefix_lengths": prefix_lengths,
        "variants": PREFIX_VARIANTS,
        "danger_u32": [f"0x{x:08x}" for x in DANGER_U32],
        "known_prefix": args.known_prefix,
        "include_known_every": args.include_known_every,
        "ax_fuzz": str(Path(args.ax_fuzz).resolve()),
        "repro": str(Path(args.repro).resolve()),
        "core_dirs": [str(p) for p in core_dirs],
        "baseline_core": baseline_core,
        "start_wall": start_wall,
    }
    json_write(out_dir / "run_config.json", config)

    ctx = mp.get_context("fork")
    stop_event = ctx.Event()
    counters = [ctx.Value("Q", 0, lock=False) for _ in range(args.workers)]
    args_dict = dict(config)
    procs = []
    for worker_id in range(args.workers):
        proc = ctx.Process(
            target=worker_main,
            args=(worker_id, args_dict, stop_event, counters[worker_id]),
            name=f"samc-ecdh-prefix-worker-{worker_id:02d}",
        )
        proc.start()
        procs.append(proc)

    print(f"out={out_dir}", flush=True)
    print(f"target={args.host}:{args.port} mode={args.mode}", flush=True)
    print(f"baseline_core={baseline_core}", flush=True)
    result: dict[str, Any] = {"reason": "unknown"}
    last_progress = 0.0
    last_listener_check = 0.0
    listener_is_ready = True
    try:
        while True:
            now = time.monotonic()
            elapsed = now - start_mono
            if elapsed >= args.timeout:
                result = {"reason": "timeout", "elapsed": elapsed}
                break
            cur_core = newest_core(core_dirs)
            changed_core = core_changed_since(baseline_core, cur_core, start_wall)
            if now - last_listener_check >= args.listener_check_interval:
                listener_is_ready = listener_ready(args.host, args.port)
                last_listener_check = now
            workers_exited = all(not p.is_alive() for p in procs)
            if changed_core or not listener_is_ready:
                result = {
                    "reason": "crash_or_restart",
                    "elapsed": elapsed,
                    "baseline_core": baseline_core,
                    "core": cur_core,
                    "core_changed": changed_core,
                    "listener_down": not listener_is_ready,
                }
                break
            if workers_exited:
                result = {"reason": "workers_exited", "elapsed": elapsed}
                break
            if now - last_progress >= args.progress_interval:
                counts = [c.value for c in counters]
                print(
                    f"progress elapsed={elapsed:.1f}s attempts={sum(counts)} "
                    f"per_worker={counts} listener={listener_is_ready}",
                    flush=True,
                )
                last_progress = now
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        result = {"reason": "interrupted", "elapsed": time.monotonic() - start_mono}
    finally:
        stop_event.set()
        for proc in procs:
            proc.join(timeout=args.worker_join_timeout)
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
        for proc in procs:
            proc.join(timeout=2.0)
        for proc in procs:
            if proc.is_alive():
                proc.kill()

    counts = [c.value for c in counters]
    attribution = write_crash_attribution(out_dir)
    summary = {
        "result": result,
        "attempts": sum(counts),
        "per_worker_attempts": counts,
        "worker_pids": [p.pid for p in procs],
        "worker_exitcodes": [p.exitcode for p in procs],
        "baseline_core": baseline_core,
        "end_core": newest_core(core_dirs),
        "listener_ready_end": listener_ready(args.host, args.port),
        "crash_attribution_count": attribution["count"],
    }
    json_write(out_dir / "summary.json", summary)
    print("summary=" + json.dumps(summary, sort_keys=True), flush=True)
    return 2 if result.get("reason") == "crash_or_restart" else 0


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="ECDH-channel prefix/dispatcher fuzzer for CodeMeterLin.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--mode", choices=["hello", "ack", "mixed"], default="hello")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--iterations", type=int, default=100000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--seed-base", type=lambda s: int(s, 0), default=0xE0000000)
    ap.add_argument("--timeout", type=float, default=900.0)
    ap.add_argument("--connect-timeout", type=float, default=2.0)
    ap.add_argument("--socket-timeout", type=float, default=1.5)
    ap.add_argument("--poll-interval", type=float, default=0.25)
    ap.add_argument("--listener-check-interval", type=float, default=0.5)
    ap.add_argument("--progress-interval", type=float, default=30.0)
    ap.add_argument("--worker-join-timeout", type=float, default=8.0)
    ap.add_argument("--opcodes", default="0x00-0xff")
    ap.add_argument("--skip-opcodes", default="")
    ap.add_argument("--prefix-lengths", default="1-32")
    ap.add_argument("--known-prefix", default=DEFAULT_KNOWN_HELLO_PREFIX)
    ap.add_argument("--include-known-every", type=int, default=0,
                    help="0 disables the known 5e355ed6f2 canary in the search stream")
    ap.add_argument("--ax-fuzz", default="/home/avj/clones/ax_fuzz")
    ap.add_argument("--repro", type=Path, default=DEFAULT_REPRO)
    ap.add_argument("--core-dir", action="append", default=[],
                    help="core directory to watch; repeatable")
    return ap


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    if args.iterations < 1:
        raise SystemExit("--iterations must be >= 1")
    if args.ring_size < 1:
        raise SystemExit("--ring-size must be >= 1")
    if args.include_known_every < 0:
        raise SystemExit("--include-known-every must be >= 0")
    if not args.core_dir:
        args.core_dir = ["/var/tmp/cm_cores", "/var/lib/systemd/coredump"]
    if not args.repro.exists():
        raise SystemExit(f"repro helper not found: {args.repro}")
    return run_supervisor(args)


if __name__ == "__main__":
    raise SystemExit(main())
