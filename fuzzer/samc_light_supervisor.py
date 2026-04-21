#!/usr/bin/env python3
"""Lightweight 16-worker SAMC fuzz orchestrator.

This is the "orchestrator" used to reduce the CodeMeterLin crash. It preserves
the important behavior of the original high-throughput fuzzer
(`../ax_fuzz/tier1/samc_fuzz.py`) while changing how crash attribution works.

What changed compared with the original parallel fuzzer:

1. Crash detection moved out of workers and into one supervisor.
   The old workers each checked daemon liveness every 10 iterations and all
   tried to save/restart when one daemon died. That made crash files mostly
   bystanders. Here, workers only fuzz. The supervisor watches the daemon and
   stops everybody together.

2. Daemon identity checks are stricter.
   The old code used `pgrep -f "/usr/sbin/CodeMeterLin -f"`, which can match
   command lines that merely contain that string. This script uses
   `pgrep -x CodeMeterLin`, plus listener/service/core checks.

3. Raw cores are part of the crash oracle.
   Full cores on this host are written under `/var/tmp/cm_cores`; older
   systemd-coredump files live under `/var/lib/systemd/coredump`. The
   supervisor watches both. A new core after run start is enough to stop.

4. Workers keep only an in-memory ring while fuzzing.
   Writing every attempt was too slow and changed timing. Each worker stores
   the last N attempts in RAM and writes them only when it exits. This keeps
   throughput close to the original fuzzer.

5. Post-crash connection-refused attempts are not allowed into the ring.
   The first version of this orchestrator reproduced the crash, but every
   worker then filled its last-100 ring with `Connection refused` attempts
   while the core was being written. The current code appends only attempts
   that actually sent at least one frame (`attempt["frames"]` is non-empty).

Output layout:

  <out-dir>/
    run_config.json                 seeds, roles, baseline PID/core
    summary.json                    supervisor result and worker counters
    worker_00/
      worker_summary.json           per-worker status counts
      ring_manifest.jsonl           JSONL index of saved attempts
      ring/iter_00004667/
        attempt.json                metadata for one attempt
        frame_0_plaintext.bin       plaintext sent for frame 0
        frame_1_plaintext.bin       if that attempt reached ACK
        frame_2_plaintext.bin       if that attempt reached 0x64

This script is not meant to be a general-purpose fuzzing framework. It is a
small crash-attribution wrapper for this specific SAMC reduction job.
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
import subprocess
import sys
import time
import traceback
from typing import Any


STRATEGIES = [
    "bitflip", "byteflip", "insert_rand", "delete",
    "extend_zero", "truncate", "dict_splice",
    "sentinel_byte",
]


def load_samc(ax_fuzz: Path):
    """Import the existing fuzzer module without copying its crypto helpers."""
    mod_path = ax_fuzz / "tier1" / "samc_fuzz.py"
    sys.path.insert(0, str(mod_path.parent))
    spec = importlib.util.spec_from_file_location("samc_fuzz", mod_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutate_with_meta(samc, plaintext: bytes, rng: random.Random) -> tuple[bytes, dict[str, Any]]:
    """Mutate one plaintext and return enough metadata to replay the choice.

    The mutator intentionally mirrors the old fuzzer's RNG call order and
    mutation semantics. That matters because we wanted the orchestrated run to
    stay comparable to the run that originally found the bug. The only extra
    work is recording metadata such as position, inserted bytes, and output
    length.
    """
    if not plaintext:
        n = rng.randint(4, 64)
        out = rng.randbytes(n)
        return out, {"strategy": "grow_empty", "len": n}

    strategy = rng.choice(STRATEGIES)
    pt = bytearray(plaintext)
    meta: dict[str, Any] = {"strategy": strategy, "input_len": len(plaintext)}

    if strategy == "bitflip" and pt:
        pos = rng.randrange(len(pt))
        bit = rng.randrange(8)
        old = pt[pos]
        pt[pos] ^= 1 << bit
        meta.update({"pos": pos, "bit": bit, "old": old, "new": pt[pos]})
    elif strategy == "byteflip" and pt:
        pos = rng.randrange(len(pt))
        old = pt[pos]
        pt[pos] = rng.randrange(256)
        meta.update({"pos": pos, "old": old, "new": pt[pos]})
    elif strategy == "insert_rand":
        pos = rng.randrange(len(pt) + 1)
        n = rng.randint(1, 16)
        data = rng.randbytes(n)
        pt[pos:pos] = data
        meta.update({"pos": pos, "insert_len": n, "insert_hex": data.hex()})
    elif strategy == "delete" and len(pt) > 1:
        pos = rng.randrange(len(pt))
        n = rng.randint(1, min(16, len(pt) - pos))
        deleted = bytes(pt[pos:pos + n])
        del pt[pos:pos + n]
        meta.update({"pos": pos, "delete_len": n, "deleted_hex": deleted.hex()})
    elif strategy == "extend_zero":
        n = rng.randint(1, 64)
        pt.extend(b"\x00" * n)
        meta.update({"append_len": n})
    elif strategy == "truncate" and len(pt) > 1:
        new_len = rng.randrange(1, len(pt))
        pt = pt[:new_len]
        meta.update({"new_len": new_len})
    elif strategy == "dict_splice":
        token = rng.choice(samc.DICT_TOKENS)
        pos = rng.randrange(len(pt) + 1)
        pt[pos:pos] = token
        meta.update({"pos": pos, "token_hex": token.hex(), "token_len": len(token)})
    elif strategy == "sentinel_byte" and pt:
        pos = rng.randrange(len(pt))
        old = pt[pos]
        pt[pos] = rng.choice([0x00, 0xff, 0x7f, 0x80, 0x01])
        meta.update({"pos": pos, "old": old, "new": pt[pos]})

    meta["output_len"] = len(pt)
    return bytes(pt), meta


def response_meta(samc, sock: socket.socket) -> tuple[dict[str, Any], bytes | None]:
    """Receive one daemon response and keep only compact diagnostic metadata."""
    try:
        wire = samc.recv_one_wire_frame(sock, timeout=1.5)
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as exc:
        return {"status": "recv_exception", "exception": f"{type(exc).__name__}:{exc}"}, None
    if wire is None:
        return {"status": "none"}, None
    inner = samc.decrypt_d2c_frame(wire, int(time.time()))
    meta: dict[str, Any] = {"status": "wire", "wire_len": len(wire), "inner_len": None}
    if inner is not None:
        meta["inner_len"] = len(inner)
        if len(inner) >= 8:
            meta["sid_hex"] = bytes(inner[4:8]).hex()
    return meta, inner


def _eager_dump_target_frame(worker_dir: Path, iteration: int, idx: int,
                             plaintext: bytes, frame: dict[str, Any]) -> None:
    """Persist a probable-trigger target-frame plaintext the instant it fails.

    The in-memory ring + post-stop `dump_ring()` already captures this data,
    but a worker can die between detection and the ring dump (OOM, SIGKILL,
    namespace teardown). Eagerly writing the plaintext to a distinct
    `target_frame_crash_candidates/` directory guarantees the probable-trigger
    bytes are on disk before `run_one` returns, independent of the ring path.
    """
    try:
        out_dir = worker_dir / "target_frame_crash_candidates"
        out_dir.mkdir(parents=True, exist_ok=True)
        bin_path = out_dir / f"iter_{iteration:08d}_frame_{idx}.bin"
        bin_path.write_bytes(plaintext)
        frame["crash_candidate_path"] = str(bin_path)
        frame["crash_candidate_sha256"] = sha256_hex(plaintext)
    except OSError:
        pass


def run_one(samc, host: str, port: int, target_frame: int,
            rng: random.Random, worker_id: int, iteration: int,
            worker_dir: Path) -> tuple[str, dict[str, Any]]:
    """Run one stateful SAMC session attempt.

    A session attempt is:

      HELLO
      optional ACK
      optional 0x64 request

    depending on which frame is the target. The target frame is mutated before
    encryption. The returned attempt object keeps plaintext bytes in memory so
    `dump_ring()` can write them if the supervisor stops the run.
    """
    sids: list[bytes] = []
    token = rng.randbytes(samc.HELLO_TOKEN_LEN)
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "target_frame": target_frame,
        "token_hex": token.hex(),
        "wall_start": time.time(),
        "mono_start_ns": time.monotonic_ns(),
        "frames": [],
        "mutation": None,
        "status": None,
        "error": None,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as exc:
        status = f"conn_error:{exc}"
        attempt["status"] = status
        attempt["error"] = f"{type(exc).__name__}:{exc}"
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        return status, attempt

    try:
        for idx in range(target_frame + 1):
            frame: dict[str, Any] = {
                "idx": idx,
                "sid_values_before": [sid.hex() for sid in sids],
            }
            pt = samc.CAPTURED_SESSION_C2D[idx]
            pt = samc.substitute_token(idx, pt, token)
            pt = samc.apply_sid_patches(idx, pt, sids)
            if idx == target_frame:
                pt, mut = mutate_with_meta(samc, pt, rng)
                attempt["mutation"] = mut
                frame["mutation"] = mut
            else:
                frame["mutation"] = {"strategy": "none"}

            frame["plaintext"] = pt
            frame["plaintext_len"] = len(pt)
            frame["send_start_mono_ns"] = time.monotonic_ns()
            wire = samc.encrypt_c2d_frame(pt, int(time.time()))
            try:
                sock.sendall(wire)
                frame["send_end_mono_ns"] = time.monotonic_ns()
            except (OSError, ConnectionResetError, BrokenPipeError) as exc:
                frame["send_end_mono_ns"] = time.monotonic_ns()
                frame["send_error"] = f"{type(exc).__name__}:{exc}"
                attempt["frames"].append(frame)
                status = "closed_early"
                attempt["status"] = status
                return status, attempt

            resp, inner = response_meta(samc, sock)
            frame["response"] = resp
            if inner is not None and len(inner) >= 8:
                sids.append(bytes(inner[4:8]))
            attempt["frames"].append(frame)

            if resp["status"] in {"none", "recv_exception"}:
                # Distinguish "session failed before we could exercise the
                # target" from "target sent but daemon went silent". The
                # latter is the primary crash-trigger candidate and must not
                # be conflated with a clean "ok" outcome.
                status = "no_response" if idx < target_frame else "target_no_response"
                attempt["status"] = status
                if idx == target_frame:
                    _eager_dump_target_frame(worker_dir, iteration, idx, pt, frame)
                return status, attempt
            if resp["status"] == "wire" and resp.get("inner_len") is None:
                # Garbled reply at the target frame is a weaker signal — in
                # sweep mode it fires constantly because the daemon rejects
                # most random opcodes this way. Don't eager-dump these; the
                # ring-manifest path still captures them if they matter.
                status = "decrypt_fail" if idx < target_frame else "target_decrypt_fail"
                attempt["status"] = status
                return status, attempt

        status = "ok"
        attempt["status"] = status
        return status, attempt
    finally:
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        try:
            sock.close()
        except OSError:
            pass


SWEEP_SID_OFFSET = 4   # bytes [4:8] host the session SID in ACK-shaped frames
SWEEP_SID_LEN = 4


def _build_sweep_body(opcode: int, body_len: int, body_seed: int,
                      prefix_zero_bytes: int, patch_sid: bool,
                      sid: bytes | None) -> bytes:
    """Construct one sweep payload with optional zero-prefix and SID patch.

    Layout (when all options are on):
      [opcode]  [0x00 * prefix_zero_bytes]  [sid[0:SID_LEN]]  [random tail]
    The random tail fills whatever length remains. `random.Random` is seeded
    by `(body_seed, opcode)` only — independent of length — so a crash
    reproduces at any length >= the crash minimum.
    """
    if body_len <= 0:
        return b""
    rng = random.Random(f"{body_seed:x}:{opcode:02x}:body")
    # Full random first, then overwrite the structured prefix in-place.
    out = bytearray(rng.randbytes(body_len))
    out[0] = opcode & 0xff
    n_zero = min(prefix_zero_bytes, body_len - 1)
    for i in range(n_zero):
        out[1 + i] = 0x00
    if patch_sid and sid is not None and body_len >= SWEEP_SID_OFFSET + SWEEP_SID_LEN:
        out[SWEEP_SID_OFFSET:SWEEP_SID_OFFSET + SWEEP_SID_LEN] = sid[:SWEEP_SID_LEN]
    return bytes(out)


def run_sweep_one(samc, host: str, port: int, opcode: int, body_len: int,
                  body_seed: int, worker_id: int, iteration: int,
                  worker_dir: Path, prefix_zero_bytes: int = 0,
                  patch_sid: bool = False) -> tuple[str, dict[str, Any]]:
    """One opcode-sweep attempt: canonical HELLO, then one crafted frame.

    Body is built by `_build_sweep_body`. The HELLO-returned SID is patched
    into bytes 4..8 of the crafted frame when `patch_sid` is on — that is the
    offset where ACK-shaped frames carry the SID (see SID_PATCHES in
    samc_fuzz.py). Opcodes whose handler expects the SID at a different
    offset will still be rejected; patching just gets us past the baseline
    ACK-shaped transport check.
    """
    attempt: dict[str, Any] = {
        "worker_id": worker_id,
        "iteration": iteration,
        "target_frame": 1,
        "opcode": opcode,
        "body_len": body_len,
        "sweep": True,
        "sweep_prefix_zero_bytes": prefix_zero_bytes,
        "sweep_patch_sid": patch_sid,
        "wall_start": time.time(),
        "mono_start_ns": time.monotonic_ns(),
        "frames": [],
        "mutation": None,
        "status": None,
        "error": None,
    }

    # random.Random accepts int/str/bytes (not tuples); encode deterministically
    # so the same (body_seed, opcode, role) triple always produces the same stream.
    token_rng = random.Random(f"{body_seed:x}:{opcode:02x}:token")
    token = token_rng.randbytes(samc.HELLO_TOKEN_LEN)
    attempt["token_hex"] = token.hex()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
    except OSError as exc:
        status = f"conn_error:{exc}"
        attempt["status"] = status
        attempt["error"] = f"{type(exc).__name__}:{exc}"
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        return status, attempt

    try:
        # Frame 0: canonical HELLO (unmutated, fresh token).
        hello_frame: dict[str, Any] = {
            "idx": 0,
            "mutation": {"strategy": "none"},
            "sid_values_before": [],
        }
        hello_pt = samc.substitute_token(0, samc.CAPTURED_SESSION_C2D[0], token)
        hello_frame["plaintext"] = hello_pt
        hello_frame["plaintext_len"] = len(hello_pt)
        hello_frame["send_start_mono_ns"] = time.monotonic_ns()
        hello_wire = samc.encrypt_c2d_frame(hello_pt, int(time.time()))
        try:
            sock.sendall(hello_wire)
            hello_frame["send_end_mono_ns"] = time.monotonic_ns()
        except (OSError, ConnectionResetError, BrokenPipeError) as exc:
            hello_frame["send_end_mono_ns"] = time.monotonic_ns()
            hello_frame["send_error"] = f"{type(exc).__name__}:{exc}"
            attempt["frames"].append(hello_frame)
            status = "closed_early"
            attempt["status"] = status
            return status, attempt

        resp0, inner0 = response_meta(samc, sock)
        hello_frame["response"] = resp0
        attempt["frames"].append(hello_frame)
        if resp0["status"] != "wire" or inner0 is None or len(inner0) < 8:
            status = "hello_no_session"
            attempt["status"] = status
            return status, attempt

        # Build the sweep body now that we have the SID to patch in.
        sid = bytes(inner0[4:8])
        body = _build_sweep_body(opcode, body_len, body_seed,
                                 prefix_zero_bytes, patch_sid, sid)

        # Frame 1: the sweep payload. Plaintext is the crafted bytes verbatim.
        sweep_frame: dict[str, Any] = {
            "idx": 1,
            "mutation": {"strategy": "sweep", "opcode": opcode,
                         "body_seed": body_seed, "body_len": body_len,
                         "prefix_zero_bytes": prefix_zero_bytes,
                         "patch_sid": patch_sid},
            "sid_values_before": [sid.hex()],
        }
        sweep_frame["plaintext"] = body
        sweep_frame["plaintext_len"] = len(body)
        sweep_frame["send_start_mono_ns"] = time.monotonic_ns()
        sweep_wire = samc.encrypt_c2d_frame(body, int(time.time()))
        try:
            sock.sendall(sweep_wire)
            sweep_frame["send_end_mono_ns"] = time.monotonic_ns()
        except (OSError, ConnectionResetError, BrokenPipeError) as exc:
            sweep_frame["send_end_mono_ns"] = time.monotonic_ns()
            sweep_frame["send_error"] = f"{type(exc).__name__}:{exc}"
            attempt["frames"].append(sweep_frame)
            status = "closed_early"
            attempt["status"] = status
            _eager_dump_target_frame(worker_dir, iteration, 1, body, sweep_frame)
            return status, attempt

        resp1, _ = response_meta(samc, sock)
        sweep_frame["response"] = resp1
        attempt["frames"].append(sweep_frame)

        if resp1["status"] in {"none", "recv_exception"}:
            status = "target_no_response"
            attempt["status"] = status
            _eager_dump_target_frame(worker_dir, iteration, 1, body, sweep_frame)
            return status, attempt
        if resp1["status"] == "wire" and resp1.get("inner_len") is None:
            # Do not eager-dump decrypt_fail in sweep mode — it is the
            # baseline response for most opcodes with random bodies.
            status = "target_decrypt_fail"
            attempt["status"] = status
            return status, attempt

        status = "ok"
        attempt["status"] = status
        return status, attempt
    finally:
        attempt["wall_end"] = time.time()
        attempt["mono_end_ns"] = time.monotonic_ns()
        try:
            sock.close()
        except OSError:
            pass


def dump_ring(worker_dir: Path, ring: collections.deque, counts: dict[str, int],
              reason: str, pid: int) -> None:
    """Write one worker's in-memory ring to disk after stop/crash.

    Plaintext bytes are written as separate `.bin` files so they can be fed to
    replay scripts or inspected with `xxd`. The JSON metadata points at those
    files and includes mutation details, response status, token, timestamps, and
    frame index.
    """
    worker_dir.mkdir(parents=True, exist_ok=True)
    ring_dir = worker_dir / "ring"
    ring_dir.mkdir(parents=True, exist_ok=True)
    manifest = worker_dir / "ring_manifest.jsonl"
    if manifest.exists():
        manifest.unlink()

    with manifest.open("a") as mf:
        for attempt in list(ring):
            attempt_dir = ring_dir / f"iter_{attempt['iteration']:08d}"
            attempt_dir.mkdir(parents=True, exist_ok=True)
            meta = dict(attempt)
            frames_meta = []
            for frame in attempt["frames"]:
                frame_meta = dict(frame)
                plaintext = frame_meta.pop("plaintext")
                path = attempt_dir / f"frame_{frame['idx']}_plaintext.bin"
                path.write_bytes(plaintext)
                frame_meta["plaintext_path"] = str(path)
                frame_meta["plaintext_sha256"] = sha256_hex(plaintext)
                frames_meta.append(frame_meta)
            meta["frames"] = frames_meta
            (attempt_dir / "attempt.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
            mf.write(json.dumps(meta, sort_keys=True) + "\n")

    (worker_dir / "worker_summary.json").write_text(json.dumps({
        "pid": pid,
        "reason": reason,
        "ring_size": len(ring),
        "status_counts": counts,
    }, indent=2, sort_keys=True) + "\n")


def worker_main(config: dict[str, Any], worker_id: int, seed: int, role: int,
                stop_event: mp.Event, counter) -> None:
    """Worker loop: fuzz quickly, keep recent sent attempts, do not restart."""
    samc = load_samc(Path(config["ax_fuzz"]))
    rng = random.Random(seed)
    n_frames = len(samc.CAPTURED_SESSION_C2D)
    ring: collections.deque = collections.deque(maxlen=config["ring_size"])
    counts: dict[str, int] = {}
    reason = "completed"
    worker_dir = Path(config["out_dir"]) / f"worker_{worker_id:02d}"

    sweep_opcodes: list[int] = []
    sweep_body_len = 0
    sweep_body_seed = 0
    sweep_body_lengths: list[int] = []
    sweep_prefix_zero_bytes = 0
    sweep_patch_sid = False
    is_sweep = config.get("mode") == "sweep"
    if is_sweep:
        sweep_opcodes = list(config.get("sweep_opcodes_per_worker", {}).get(worker_id, []))
        sweep_body_len = int(config.get("sweep_body_len", 712))
        sweep_body_seed = int(config.get("sweep_body_seed", 0xB0D1E5))
        sweep_body_lengths = list(config.get("sweep_body_lengths", []))
        sweep_prefix_zero_bytes = int(config.get("sweep_prefix_zero_bytes", 0))
        sweep_patch_sid = bool(config.get("sweep_patch_sid", False))

    try:
        for i in range(config["iterations"]):
            if stop_event.is_set():
                reason = "stop_event"
                break
            if is_sweep:
                if not sweep_opcodes:
                    reason = "no_opcodes"
                    break
                opcode = sweep_opcodes[i % len(sweep_opcodes)]
                # When --sweep-body-lengths is given, cycle lengths as an
                # additional dimension so each iteration picks a new (opcode,
                # length) combination.
                if sweep_body_lengths:
                    this_body_len = sweep_body_lengths[i % len(sweep_body_lengths)]
                else:
                    this_body_len = sweep_body_len
                target_frame = 1
            else:
                opcode = None
                target_frame = role if role >= 0 else i % n_frames
            try:
                if is_sweep:
                    status, attempt = run_sweep_one(
                        samc, config["host"], config["port"],
                        opcode, this_body_len, sweep_body_seed,
                        worker_id, i, worker_dir,
                        prefix_zero_bytes=sweep_prefix_zero_bytes,
                        patch_sid=sweep_patch_sid,
                    )
                else:
                    status, attempt = run_one(
                        samc, config["host"], config["port"], target_frame, rng,
                        worker_id, i, worker_dir,
                    )
            except BaseException:
                status = "worker_exception"
                attempt = {
                    "worker_id": worker_id,
                    "iteration": i,
                    "target_frame": target_frame,
                    "opcode": opcode,
                    "sweep": is_sweep,
                    "status": status,
                    "error": traceback.format_exc(),
                    "frames": [],
                    "wall_start": time.time(),
                    "wall_end": time.time(),
                    "mono_start_ns": time.monotonic_ns(),
                    "mono_end_ns": time.monotonic_ns(),
                }
            counts[status] = counts.get(status, 0) + 1
            # Only attempts that sent at least one frame are useful for crash
            # attribution. After a daemon crash, workers can loop through many
            # fast `Connection refused` attempts before the supervisor notices
            # the new core. Do not let those empty attempts evict the real
            # pre-crash traffic from the ring.
            if attempt.get("frames"):
                ring.append(attempt)
            counter.value = i + 1
    finally:
        dump_ring(worker_dir, ring, counts, reason, os.getpid())


def write_crash_attribution(out_dir: Path) -> dict[str, Any]:
    """Aggregate target-frame failure events across workers and sort by time.

    When N workers share a daemon, a single daemon crash can surface as
    target-frame failures on many workers — but only the worker whose send
    actually tipped the daemon into the crash is the real trigger. `CLOCK_MONOTONIC`
    is shared across processes on Linux, so `send_start_mono_ns` is directly
    comparable. The earliest event is the most likely trigger; later events
    from other workers are bystanders that saw the corpse.

    Output: `<out_dir>/crash_attribution.json` with events sorted ascending
    by `send_start_mono_ns`. Readers should treat `events[0]` as the probable
    trigger and compare subsequent entries' timestamps to decide how tight
    the attribution is.
    """
    events: list[dict[str, Any]] = []
    for worker_dir in sorted(out_dir.glob("worker_*")):
        manifest = worker_dir / "ring_manifest.jsonl"
        if not manifest.exists():
            continue
        with manifest.open() as mf:
            for line in mf:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("status") not in {"target_no_response", "target_decrypt_fail"}:
                    continue
                target_frame = entry.get("target_frame")
                tf_frame = next(
                    (f for f in entry.get("frames", []) if f.get("idx") == target_frame),
                    None,
                )
                if tf_frame is None:
                    continue
                events.append({
                    "worker_id": entry.get("worker_id"),
                    "iteration": entry.get("iteration"),
                    "target_frame": target_frame,
                    "status": entry.get("status"),
                    "send_start_mono_ns": tf_frame.get("send_start_mono_ns"),
                    "send_end_mono_ns": tf_frame.get("send_end_mono_ns"),
                    "plaintext_path": tf_frame.get("plaintext_path"),
                    "plaintext_sha256": tf_frame.get("plaintext_sha256"),
                    "crash_candidate_path": tf_frame.get("crash_candidate_path"),
                    "mutation": tf_frame.get("mutation"),
                })
    events.sort(key=lambda e: (e["send_start_mono_ns"] is None, e["send_start_mono_ns"] or 0))
    report = {"count": len(events), "events": events}
    (out_dir / "crash_attribution.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    return report


def sh(args: list[str], timeout: float = 2.0) -> str:
    return subprocess.check_output(args, text=True, timeout=timeout).strip()


def codemeter_pid() -> int | None:
    """Return the daemon PID using an exact process-name match."""
    try:
        out = sh(["pgrep", "-x", "CodeMeterLin"])
    except Exception:
        return None
    pids = [int(tok) for tok in out.split() if tok.isdigit()]
    return pids[0] if pids else None


def service_state() -> str:
    try:
        return sh(["systemctl", "is-active", "codemeter"])
    except Exception as exc:
        return f"unknown:{type(exc).__name__}"


DEFAULT_CORE_DIRS = (Path("/var/tmp/cm_cores"), Path("/var/lib/systemd/coredump"))


def newest_core(core_dirs: tuple[Path, ...] = DEFAULT_CORE_DIRS) -> dict[str, Any] | None:
    """Return the newest CodeMeter core from the configured core directories."""
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


def listener_ready(port: int) -> bool:
    """Check whether the CodeMeter TCP listener is accepting on `port`."""
    try:
        out = sh(["ss", "-tln", f"( sport = :{port} )"])
    except Exception:
        return False
    return f":{port}" in out


def ensure_daemon(port: int, check_service: bool = True) -> None:
    """Start CodeMeter if needed and wait until PID and listener are visible.

    When `check_service` is False (used inside namespaced fuzz farms where the
    in-ns daemon is not systemd-managed), skip the systemctl probe/start
    entirely and only poll for PID + listener.
    """
    if check_service and service_state() != "active":
        subprocess.run(["sudo", "systemctl", "start", "codemeter"], check=False, timeout=30)
    for _ in range(30):
        if codemeter_pid() and listener_ready(port):
            return
        time.sleep(1)
    raise RuntimeError("codemeter is not ready")


def _parse_opcode_spec(spec: str) -> list[int]:
    """Parse '0x00-0xff' / '0x01,0x20-0x2f,0x5e' into a sorted unique list.

    Accepts decimal or 0x-prefixed hex. Ranges inclusive on both ends.
    Silently skips empty comma segments so callers can splice lists.
    """
    values: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo = int(lo_s.strip(), 0)
            hi = int(hi_s.strip(), 0)
            if lo > hi:
                lo, hi = hi, lo
            values.update(range(lo, hi + 1))
        else:
            values.add(int(chunk, 0))
    return sorted(v & 0xff for v in values)


def roles_for(workers: int, mode: str) -> list[int]:
    """Map worker IDs to fuzzing roles.

    Role values are frame indexes:

      -1 = rotate target frame by iteration
       0 = mutate HELLO
       1 = mutate ACK
       2 = mutate 0x64

    `mixed` matches the original 16-worker shape: rotate, HELLO, ACK, BIG,
    repeated across the worker list.
    """
    patterns = {
        "mixed": [-1, 0, 1, 2],
        "rotate": [-1],
        "hello": [0],
        "ack": [1],
        "big": [2],
        # Sweep mode doesn't use `role`; the per-worker opcode list is
        # plumbed through config instead. Stub a value so callers that
        # still iterate `roles` keep working.
        "sweep": [-1],
    }
    pattern = patterns[mode]
    return [pattern[i % len(pattern)] for i in range(workers)]


def supervisor(args: argparse.Namespace) -> int:
    """Start workers, watch the daemon, stop on the first crash signal."""
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_daemon(args.port, check_service=not args.no_service_check)

    core_dirs = tuple(Path(d) for d in args.core_dir) if args.core_dir else DEFAULT_CORE_DIRS
    baseline_pid = codemeter_pid()
    baseline_core = newest_core(core_dirs)
    start_wall = time.time()
    start_mono = time.monotonic()
    roles = roles_for(args.workers, args.mode)
    seeds = [args.seed_base + i for i in range(args.workers)]

    config = {
        "ax_fuzz": str(Path(args.ax_fuzz).resolve()),
        "out_dir": str(out_dir),
        "host": args.host,
        "port": args.port,
        "iterations": args.iterations,
        "ring_size": args.ring_size,
        "mode": args.mode,
    }

    sweep_opcodes_per_worker: dict[int, list[int]] = {}
    if args.mode == "sweep":
        all_opcodes = _parse_opcode_spec(args.sweep_opcodes)
        skip = set(_parse_opcode_spec(args.sweep_skip_opcodes)) if args.sweep_skip_opcodes else set()
        all_opcodes = [op for op in all_opcodes if op not in skip]
        if not all_opcodes:
            raise SystemExit(
                f"--sweep-opcodes/--sweep-skip-opcodes combination is empty: "
                f"include={args.sweep_opcodes!r} skip={args.sweep_skip_opcodes!r}"
            )
        sweep_opcodes_per_worker = {
            w: all_opcodes[w::args.workers] for w in range(args.workers)
        }
        config["sweep_opcodes_per_worker"] = sweep_opcodes_per_worker
        config["sweep_body_len"] = args.sweep_body_len
        config["sweep_body_seed"] = args.sweep_body_seed
        config["sweep_skip_opcodes"] = sorted(skip)
        config["sweep_prefix_zero_bytes"] = int(args.sweep_prefix_zero_bytes)
        config["sweep_patch_sid"] = bool(args.sweep_patch_sid)
        if args.sweep_body_lengths:
            lens = [int(x, 0) for x in args.sweep_body_lengths.split(",") if x.strip()]
            if not lens:
                raise SystemExit(f"--sweep-body-lengths empty: {args.sweep_body_lengths!r}")
            config["sweep_body_lengths"] = lens
        else:
            config["sweep_body_lengths"] = []

    run_config_blob: dict[str, Any] = {
        "config": {k: v for k, v in config.items() if k != "sweep_opcodes_per_worker"},
        "workers": args.workers,
        "mode": args.mode,
        "roles": roles,
        "seeds": seeds,
        "baseline_pid": baseline_pid,
        "baseline_core": baseline_core,
        "start_wall": start_wall,
    }
    if args.mode == "sweep":
        run_config_blob["sweep"] = {
            "opcode_spec": args.sweep_opcodes,
            "skip_spec": args.sweep_skip_opcodes,
            "skip_resolved": sorted(set(_parse_opcode_spec(args.sweep_skip_opcodes)) if args.sweep_skip_opcodes else set()),
            "body_len": args.sweep_body_len,
            "body_seed": args.sweep_body_seed,
            "body_lengths": config.get("sweep_body_lengths", []),
            "prefix_zero_bytes": int(args.sweep_prefix_zero_bytes),
            "patch_sid": bool(args.sweep_patch_sid),
            "opcodes_per_worker": {str(k): v for k, v in sweep_opcodes_per_worker.items()},
        }
    (out_dir / "run_config.json").write_text(json.dumps(run_config_blob, indent=2, sort_keys=True) + "\n")

    stop_event = mp.Event()
    counters = [mp.Value("Q", 0, lock=False) for _ in range(args.workers)]
    procs: list[mp.Process] = []
    for worker_id, (seed, role) in enumerate(zip(seeds, roles)):
        proc = mp.Process(
            target=worker_main,
            args=(config, worker_id, seed, role, stop_event, counters[worker_id]),
            name=f"samc-light-worker-{worker_id:02d}",
        )
        proc.start()
        procs.append(proc)

    print(f"out={out_dir}", flush=True)
    print(f"baseline_pid={baseline_pid}", flush=True)
    print(f"baseline_core={baseline_core}", flush=True)
    print(f"workers={[p.pid for p in procs]}", flush=True)

    result: dict[str, Any] = {"reason": "unknown"}
    last_progress = time.monotonic()
    last_listener_check = 0.0
    last_service_check = 0.0
    listener_is_ready = True
    current_service_state = "active"

    try:
        while True:
            now = time.monotonic()
            if now - start_mono >= args.timeout:
                result = {"reason": "timeout", "elapsed": now - start_mono}
                break

            cur_pid = codemeter_pid()
            cur_core = newest_core(core_dirs)
            if now - last_listener_check >= args.listener_check_interval:
                listener_is_ready = listener_ready(args.port)
                last_listener_check = now
            if not args.no_service_check and now - last_service_check >= args.service_check_interval:
                current_service_state = service_state()
                last_service_check = now
            core_changed = (
                cur_core is not None and
                (baseline_core is None or
                 cur_core["path"] != baseline_core["path"] or
                 cur_core["mtime_ns"] != baseline_core["mtime_ns"]) and
                cur_core["mtime_ns"] >= int(start_wall * 1_000_000_000)
            )
            pid_changed = cur_pid != baseline_pid
            listener_down = not listener_is_ready
            service_inactive = (not args.no_service_check) and current_service_state != "active"
            workers_exited = all(not p.is_alive() for p in procs)
            # Stop on the earliest reliable crash signal. A core may take a
            # moment to finish writing, and systemd may still report `active`
            # briefly, so use the union of PID/core/listener/service checks.
            if pid_changed or core_changed or listener_down or service_inactive:
                result = {
                    "reason": "crash_or_restart",
                    "elapsed": now - start_mono,
                    "baseline_pid": baseline_pid,
                    "pid": cur_pid,
                    "baseline_core": baseline_core,
                    "core": cur_core,
                    "pid_changed": pid_changed,
                    "core_changed": core_changed,
                    "listener_down": listener_down,
                    "service_inactive": service_inactive,
                    "service_state": current_service_state,
                }
                break
            if workers_exited:
                result = {"reason": "workers_exited", "elapsed": now - start_mono}
                break

            if now - last_progress >= args.progress_interval:
                counts = [c.value for c in counters]
                print(
                    f"progress elapsed={now - start_mono:.1f}s "
                    f"attempts={sum(counts)} per_worker={counts} "
                    f"pid={cur_pid} listener={listener_is_ready} service={current_service_state}",
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
            proc.join(timeout=2)
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
        "end_pid": codemeter_pid(),
        "end_core": newest_core(core_dirs),
        "end_service_state": "skipped" if args.no_service_check else service_state(),
        "crash_attribution_count": attribution["count"],
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("summary=" + json.dumps(summary, sort_keys=True), flush=True)
    return 2 if result.get("reason") == "crash_or_restart" else 0


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="High-throughput SAMC fuzz orchestrator with crash attribution.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--ax-fuzz", default="/home/avj/clones/ax_fuzz")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--mode", choices=["mixed", "rotate", "hello", "ack", "big", "sweep"], default="mixed")
    ap.add_argument("--iterations", type=int, default=10_000_000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--seed-base", type=lambda s: int(s, 0), default=0xC0D30000)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--poll-interval", type=float, default=0.25)
    ap.add_argument("--listener-check-interval", type=float, default=1.0)
    ap.add_argument("--service-check-interval", type=float, default=1.0)
    ap.add_argument("--progress-interval", type=int, default=30)
    ap.add_argument("--worker-join-timeout", type=float, default=8.0)
    ap.add_argument("--no-service-check", action="store_true",
                    help="skip systemctl probes (use inside namespaced fuzz farms where "
                         "the daemon is not systemd-managed)")
    ap.add_argument("--core-dir", action="append",
                    help="core-dump directory to watch; repeat to watch multiple. "
                         "Default: /var/tmp/cm_cores and /var/lib/systemd/coredump. "
                         "Inside a namespaced farm, restrict to the farm-private dir "
                         "so cross-farm crashes don't masquerade as self-crashes.")
    ap.add_argument("--sweep-body-len", type=int, default=712,
                    help="Length in bytes of the sweep frame (byte 0 = opcode, "
                         "remainder deterministic random). Only used when --mode=sweep.")
    ap.add_argument("--sweep-body-seed", type=lambda s: int(s, 0), default=0xB0D1E5,
                    help="Base seed for the sweep body PRNG. Same seed + same opcode "
                         "always produces the same body so crashes are reproducible. "
                         "Only used when --mode=sweep.")
    ap.add_argument("--sweep-opcodes", type=str, default="0x00-0xff",
                    help="Opcode range or list to sweep, e.g. '0x00-0xff' or "
                         "'0x01,0x20-0x2f,0x5e'. Workers split the union by stride.")
    ap.add_argument("--sweep-skip-opcodes", type=str, default="",
                    help="Opcode list/range to exclude from the sweep, same syntax as "
                         "--sweep-opcodes. Use to skip opcodes that trigger a known "
                         "bug and shadow the rest of the opcode space.")
    ap.add_argument("--sweep-prefix-zero-bytes", type=int, default=0,
                    help="After the opcode byte, write N zero bytes before the random "
                         "tail. Mirrors the '00 00 00' shape of the captured C2D frames "
                         "and is more likely to clear transport-layer checks.")
    ap.add_argument("--sweep-patch-sid", action="store_true",
                    help="Patch the HELLO-returned SID into bytes [4:8] of the crafted "
                         "frame. Gets handlers that gate on session-is-valid past that "
                         "check. Requires body_len >= 8.")
    ap.add_argument("--sweep-body-lengths", type=str, default="",
                    help="Comma-separated list of lengths to cycle through per iteration "
                         "(e.g. '4,8,12,16,40,100,712'). Overrides --sweep-body-len. "
                         "Each (opcode, length) pair is tested; a worker at iteration i "
                         "picks lengths[i % N].")
    return ap.parse_args()


def main() -> int:
    return supervisor(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
