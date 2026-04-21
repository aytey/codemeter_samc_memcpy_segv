#!/usr/bin/env python3
"""Multi-instance CodeMeterLin fuzz farm launcher.

Spawns N isolated CodeMeterLin daemons, each in its own Linux namespace set
(mount, IPC, network, PID, UTS), and runs one samc_light_supervisor.py with
W workers inside each. See MULTI_INSTANCE_FUZZING.md for the isolation set
rationale (including the /tmp/cm_lock singleton finding).

Must be run as root (invoke with sudo). Each farm is one host-side process
tree:

    sudo -> unshare --fork --kill-child=SIGINT --pid --mount-proc --mount --ipc --net --uts
         -> bash fuzz_farm_namespace_init.sh  (namespace PID 1)
         -> execs python3 samc_light_supervisor.py

SIGTERM to the driver propagates: sudo forwards to unshare, unshare's
--kill-child sends SIGINT to the supervisor, which already has a clean
KeyboardInterrupt path that dumps worker rings and writes summary.json.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_INIT_SCRIPT = HERE / "fuzz_farm_namespace_init.sh"
DEFAULT_SUPERVISOR = HERE / "samc_light_supervisor.py"

# Cycled across farms so a 6-farm run exercises every mode at least once.
DEFAULT_MODES = ["mixed", "hello", "ack", "big", "rotate", "mixed"]

# Signature bucketing. Key = first binary-local frame offset.
# Seeded with the crash this repo was created to reproduce.
KNOWN_SIGNATURES: dict[str, str] = {
    "CodeMeterLin+0x8f431d": "memcpy_8f431d_prefixed_hello",
}


def extract_signature(core_path: Path, binary: Path,
                      n_frames: int = 8, timeout: float = 60.0) -> dict[str, Any]:
    """Extract a crash signature from a core: base address + top-N frame offsets.

    Runs `gdb -batch` with `info proc mappings` and `bt N`, parses the
    CodeMeterLin mapping base from mappings, then renders each frame PC as
    either `<binary>+0xNNN` (if inside the binary) or raw `0xNNN`.
    """
    try:
        out = subprocess.run(
            ["gdb", "-batch", "-nx", "-q", str(binary), str(core_path),
             "-ex", "info proc mappings",
             "-ex", f"bt {n_frames}"],
            check=False, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "gdb_timeout", "frames": [], "base": None}

    text = (out.stdout or "") + "\n" + (out.stderr or "")
    base: int | None = None
    # `info proc mappings` lines end with the mapped file path. Take the lowest
    # start address whose mapping is our binary.
    for line in text.splitlines():
        line = line.strip()
        if not line.endswith(binary.name):
            continue
        parts = line.split()
        if parts and parts[0].startswith("0x"):
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if base is None or addr < base:
                base = addr

    raw_frames: list[int] = []
    for line in text.splitlines():
        m = re.match(r"^#(\d+)\s+(0x[0-9a-fA-F]+)", line.strip())
        if m:
            raw_frames.append(int(m.group(2), 16))

    frames: list[str] = []
    for pc in raw_frames:
        if base is not None and base <= pc < base + 0x20000000:
            frames.append(f"{binary.name}+0x{pc - base:x}")
        else:
            frames.append(f"0x{pc:x}")

    return {
        "base": f"0x{base:x}" if base is not None else None,
        "frames": frames,
        "raw_pc": [f"0x{pc:x}" for pc in raw_frames],
    }


def classify_signature(sig: dict[str, Any]) -> str:
    """Bucket name. Uses the first binary-local frame; returns 'new:<frame>' if unknown."""
    for f in sig.get("frames", []):
        if f.startswith("CodeMeterLin+"):
            if f in KNOWN_SIGNATURES:
                return KNOWN_SIGNATURES[f]
            return f"new:{f}"
    return "unknown_no_binary_frame"


def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit("fuzz_farm_launcher.py must run as root (use sudo)")


def build_farm_root(farm_root: Path) -> None:
    """Create the farm's private tree and seed it from the host's CodeMeter state."""
    subdirs = [
        "etc/wibu/CodeMeter",
        "var/lib/CodeMeter",
        "var/log/CodeMeter",
        "run/lock",
        "var/tmp/cm_cores",
        "work",
    ]
    for sd in subdirs:
        (farm_root / sd).mkdir(parents=True, exist_ok=True)

    copies = [
        ("/etc/wibu/CodeMeter", "etc/wibu/CodeMeter"),
        ("/var/lib/CodeMeter", "var/lib/CodeMeter"),
        ("/var/log/CodeMeter", "var/log/CodeMeter"),
    ]
    for src, dst_rel in copies:
        dst = farm_root / dst_rel
        if not any(dst.iterdir()):
            subprocess.check_call(["cp", "-a", f"{src}/.", str(dst)])

    subprocess.check_call([
        "chown", "-R", "daemon:daemon",
        str(farm_root / "work"),
        str(farm_root / "var/tmp/cm_cores"),
    ])


def spawn_farm(
    farm_idx: int,
    farm_root: Path,
    out_dir: Path,
    init_script: Path,
    supervisor: Path,
    ax_fuzz: Path,
    workers: int,
    seed_base: int,
    mode: str,
    iterations: int,
    ring_size: int,
    timeout: int,
    port: int,
    codemeter_bin: Path,
    sweep_body_len: int = 712,
    sweep_body_seed: int = 0xB0D1E5,
    sweep_opcodes: str = "0x00-0xff",
    sweep_skip_opcodes: str = "",
    sweep_prefix_zero_bytes: int = 0,
    sweep_patch_sid: bool = False,
    sweep_body_lengths: str = "",
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ready_file = out_dir / "ready"
    daemon_log = out_dir / "daemon.log"
    ns_log = out_dir / "namespace.log"
    for p in (ready_file,):
        if p.exists():
            p.unlink()

    env = os.environ.copy()
    env.update({
        "FARM_ROOT": str(farm_root),
        "FARM_HOSTNAME": f"cmfarm{farm_idx:02d}",
        "CODEMETER_BIN": str(codemeter_bin),
        "SUPERVISOR": str(supervisor),
        "SUPERVISOR_OUT_DIR": str(out_dir),
        "AX_FUZZ": str(ax_fuzz),
        "WORKERS": str(workers),
        "SEED_BASE": f"0x{seed_base:08X}",
        "MODE": mode,
        "ITERATIONS": str(iterations),
        "TIMEOUT": str(timeout),
        "RING_SIZE": str(ring_size),
        "PORT": str(port),
        "READY_FILE": str(ready_file),
        "DAEMON_LOG": str(daemon_log),
        "SWEEP_BODY_LEN": str(sweep_body_len),
        "SWEEP_BODY_SEED": f"0x{sweep_body_seed:X}",
        "SWEEP_OPCODES": sweep_opcodes,
        "SWEEP_SKIP_OPCODES": sweep_skip_opcodes,
        "SWEEP_PREFIX_ZERO_BYTES": str(sweep_prefix_zero_bytes),
        "SWEEP_PATCH_SID": "1" if sweep_patch_sid else "0",
        "SWEEP_BODY_LENGTHS": sweep_body_lengths,
    })

    log_fh = ns_log.open("wb")
    # --kill-child=SIGINT: when unshare dies (e.g. we SIGTERM its sudo parent),
    # send SIGINT to the namespace init. The supervisor's KeyboardInterrupt
    # path already handles that cleanly.
    cmd = [
        "unshare",
        "--fork", "--kill-child=SIGINT",
        "--pid", "--mount-proc",
        "--mount", "--ipc", "--net", "--uts",
        "bash", str(init_script),
    ]
    proc = subprocess.Popen(
        cmd, env=env, stdout=log_fh, stderr=log_fh,
        preexec_fn=os.setsid,
    )
    return {
        "farm_idx": farm_idx,
        "proc": proc,
        "ns_log": ns_log,
        "daemon_log": daemon_log,
        "ready_file": ready_file,
        "out_dir": out_dir,
        "farm_root": farm_root,
        "mode": mode,
        "seed_base": seed_base,
        "workers": workers,
        "log_fh": log_fh,
    }


def wait_for_ready(farm: dict[str, Any], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if farm["ready_file"].exists():
            return True
        if farm["proc"].poll() is not None:
            return False
        time.sleep(0.5)
    return False


def stop_farm(farm: dict[str, Any], grace: float = 15.0) -> None:
    proc = farm["proc"]
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def run_dir_for(out_root: Path, farm_idx: int, run_idx: int) -> Path:
    return out_root / f"farm_{farm_idx:02d}" / f"run_{run_idx}"


def seed_base_for_run(original: int, run_idx: int, stride: int = 0x10000) -> int:
    """Offset the seed base so each restart starts from an unvisited region."""
    return original + run_idx * stride


def _spawn_one_run(farm_state: dict[str, Any], args: argparse.Namespace,
                   out_root: Path) -> None:
    """Spawn the current run for this farm; mutate farm_state in place."""
    out_dir = run_dir_for(out_root, farm_state["farm_idx"], farm_state["run_idx"])
    farm = spawn_farm(
        farm_idx=farm_state["farm_idx"],
        farm_root=farm_state["farm_root"],
        out_dir=out_dir,
        init_script=args.init_script,
        supervisor=args.supervisor,
        ax_fuzz=args.ax_fuzz,
        workers=farm_state["workers"],
        seed_base=farm_state["seed_base"],
        mode=farm_state["mode"],
        iterations=args.iterations,
        ring_size=args.ring_size,
        timeout=args.timeout,
        port=args.port,
        codemeter_bin=args.codemeter_bin,
        sweep_body_len=args.sweep_body_len,
        sweep_body_seed=args.sweep_body_seed,
        sweep_opcodes=args.sweep_opcodes,
        sweep_skip_opcodes=args.sweep_skip_opcodes,
        sweep_prefix_zero_bytes=args.sweep_prefix_zero_bytes,
        sweep_patch_sid=args.sweep_patch_sid,
        sweep_body_lengths=args.sweep_body_lengths,
    )
    # Merge per-run process handles into the persistent state dict.
    for k in ("proc", "log_fh", "ready_file", "ns_log", "daemon_log", "out_dir"):
        farm_state[k] = farm[k]
    farm_state["started_at"] = time.time()


def _process_exit(farm_state: dict[str, Any], rc: int,
                  args: argparse.Namespace) -> dict[str, Any]:
    """Read summary.json for the just-exited run and produce a history entry.

    Synchronously gdb's the core (if any) to produce a signature and
    classification. Blocking here is acceptable: crashes are rare enough that
    the ~few seconds gdb takes are not a bottleneck for a 15-min run.
    """
    run_out = farm_state["out_dir"]
    summary_path = run_out / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
    else:
        summary = {"result": {"reason": "no_summary"}, "attempts": 0}
    reason = summary.get("result", {}).get("reason", "unknown")
    entry: dict[str, Any] = {
        "run_idx": farm_state["run_idx"],
        "seed_base": f"0x{farm_state['seed_base']:08X}",
        "rc": rc,
        "reason": reason,
        "elapsed": summary.get("result", {}).get("elapsed"),
        "attempts": summary.get("attempts"),
        "out_dir": str(run_out),
        "classification": None,
        "signature": None,
    }

    core_meta = summary.get("result", {}).get("core") if reason == "crash_or_restart" else None
    if core_meta and core_meta.get("path"):
        # The supervisor records the core path as it saw it inside the
        # namespace (e.g. /var/tmp/cm_cores/core.CodeMeterLin.17.XXX).
        # That bind-mount source on the host is farm_root/var/tmp/cm_cores/<basename>.
        in_ns = Path(core_meta["path"])
        host_core = farm_state["farm_root"] / "var/tmp/cm_cores" / in_ns.name
        if host_core.exists():
            sig = extract_signature(host_core, args.codemeter_bin)
            cls = classify_signature(sig)
            entry["signature"] = sig
            entry["classification"] = cls
            entry["core_path_host"] = str(host_core)
            entry["core_size"] = host_core.stat().st_size
            # Core-disk policy: at most one exemplar per (farm, signature),
            # regardless of known/unknown. Signature + input-identity are
            # enough to reproduce; an exemplar buys us a gdb-able backtrace
            # for the first time each farm saw the signature.
            #
            # --keep-known-cores overrides: keep every known-signature core.
            # New signatures: always get the first-per-farm exemplar, rest
            # deleted. This is critical for unattended overnight runs where
            # a new bug that fires 100×/hr would otherwise fill the disk.
            is_known = cls in KNOWN_SIGNATURES.values()
            first_seen = farm_state.setdefault("first_core_per_sig", {})
            should_keep = False
            if args.keep_known_cores and is_known:
                should_keep = True
                entry["core_kept_reason"] = "keep_known_cores"
            elif cls not in first_seen:
                should_keep = True
                first_seen[cls] = str(host_core)
                entry["core_kept_reason"] = (
                    "first_exemplar_new" if not is_known else "first_exemplar_known"
                )
            if not should_keep:
                try:
                    host_core.unlink()
                    entry["core_deleted"] = True
                except OSError as exc:
                    entry["core_delete_error"] = f"{type(exc).__name__}:{exc}"
        else:
            entry["classification"] = "core_missing"
            entry["core_path_host"] = str(host_core)
    return entry


def _append_history(farm_state: dict[str, Any], entry: dict[str, Any],
                    out_root: Path) -> None:
    farm_state["history"].append(entry)
    hist_path = out_root / f"farm_{farm_state['farm_idx']:02d}" / "history.jsonl"
    hist_path.parent.mkdir(parents=True, exist_ok=True)
    with hist_path.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Launch N isolated CodeMeterLin fuzz farms with crash-signature bucketing and auto-restart.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--farms", type=int, default=6)
    ap.add_argument("--workers-per-farm", type=int, default=8)
    ap.add_argument("--root", type=Path, default=Path("/var/tmp/cm_farms"))
    ap.add_argument("--out-root", type=Path, default=None,
                    help="default: /home/avj/clones/ax_fuzz/output/farms/<timestamp>")
    ap.add_argument("--iterations", type=int, default=10_000_000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=900,
                    help="per-run supervisor timeout in seconds")
    ap.add_argument("--wall-clock", type=int, default=900,
                    help="total run budget across all restarts, in seconds")
    ap.add_argument("--max-runs-per-farm", type=int, default=0,
                    help="0 = unlimited; otherwise cap total runs per farm")
    ap.add_argument("--seed-base-origin", type=lambda s: int(s, 0), default=0xC0000000)
    ap.add_argument("--seed-base-stride", type=lambda s: int(s, 0), default=0x01000000)
    ap.add_argument("--restart-seed-stride", type=lambda s: int(s, 0), default=0x10000,
                    help="how much to advance a farm's seed base on each restart")
    ap.add_argument("--modes", type=str, default=",".join(DEFAULT_MODES),
                    help="comma-separated list cycled across farms")
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--codemeter-bin", type=Path, default=Path("/usr/sbin/CodeMeterLin"))
    ap.add_argument("--supervisor", type=Path, default=DEFAULT_SUPERVISOR)
    ap.add_argument("--ax-fuzz", type=Path, default=Path("/home/avj/clones/ax_fuzz"))
    ap.add_argument("--init-script", type=Path, default=DEFAULT_INIT_SCRIPT)
    ap.add_argument("--ready-timeout", type=float, default=60.0,
                    help="how long to wait for each farm's listener to come up")
    ap.add_argument("--keep-known-cores", action="store_true",
                    help="preserve ALL cores matching a known signature. Default: "
                         "one exemplar per (farm, known signature), rest deleted. "
                         "New signatures always get one exemplar per farm regardless.")
    ap.add_argument("--sweep-body-len", type=int, default=712,
                    help="body length for --mode sweep (forwarded to supervisor)")
    ap.add_argument("--sweep-body-seed", type=lambda s: int(s, 0), default=0xB0D1E5,
                    help="body PRNG seed for --mode sweep (forwarded to supervisor)")
    ap.add_argument("--sweep-opcodes", type=str, default="0x00-0xff",
                    help="opcode spec for --mode sweep (forwarded to supervisor)")
    ap.add_argument("--sweep-skip-opcodes", type=str, default="",
                    help="opcode spec to exclude from --mode sweep (forwarded to supervisor)")
    ap.add_argument("--sweep-prefix-zero-bytes", type=int, default=0,
                    help="N zero bytes after the opcode in the crafted frame (forwarded)")
    ap.add_argument("--sweep-patch-sid", action="store_true",
                    help="patch HELLO-returned SID into bytes [4:8] of the crafted frame "
                         "(forwarded to supervisor)")
    ap.add_argument("--sweep-body-lengths", type=str, default="",
                    help="comma-separated body lengths to cycle per iteration (forwarded)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.dry_run:
        require_root()

    if not args.init_script.exists():
        sys.exit(f"init script not found: {args.init_script}")
    if not args.supervisor.exists():
        sys.exit(f"supervisor not found: {args.supervisor}")
    if not args.codemeter_bin.exists():
        sys.exit(f"codemeter binary not found: {args.codemeter_bin}")

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if not modes:
        sys.exit("--modes produced an empty list")

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = args.out_root or Path(f"/home/avj/clones/ax_fuzz/output/farms/{ts}")
    out_root.mkdir(parents=True, exist_ok=True)

    plan = []
    for i in range(args.farms):
        plan.append({
            "farm_idx": i,
            "farm_root": args.root / f"farm_{i:02d}",
            "out_dir": out_root / f"farm_{i:02d}",
            "mode": modes[i % len(modes)],
            "seed_base": args.seed_base_origin + i * args.seed_base_stride,
            "workers": args.workers_per_farm,
        })

    (out_root / "launcher_config.json").write_text(json.dumps({
        "timestamp": ts,
        "farms": args.farms,
        "workers_per_farm": args.workers_per_farm,
        "iterations": args.iterations,
        "ring_size": args.ring_size,
        "timeout": args.timeout,
        "wall_clock": args.wall_clock,
        "max_runs_per_farm": args.max_runs_per_farm,
        "restart_seed_stride": f"0x{args.restart_seed_stride:X}",
        "port": args.port,
        "modes": modes,
        "root": str(args.root),
        "out_root": str(out_root),
        "known_signatures": KNOWN_SIGNATURES,
        "plan": [
            {**p, "farm_root": str(p["farm_root"]), "out_dir": str(p["out_dir"])}
            for p in plan
        ],
    }, indent=2) + "\n")

    print(f"out_root={out_root}")
    print(f"farm_root_base={args.root}")
    print(
        f"farms={args.farms} workers_per_farm={args.workers_per_farm} "
        f"port={args.port} wall_clock={args.wall_clock}s per_run_timeout={args.timeout}s"
    )
    for p in plan:
        print(
            f"  farm_{p['farm_idx']:02d}: mode={p['mode']:>6} "
            f"seed_base=0x{p['seed_base']:08X} root={p['farm_root']}"
        )

    if args.dry_run:
        return 0

    for p in plan:
        print(f"[setup] farm_{p['farm_idx']:02d} root={p['farm_root']}")
        build_farm_root(p["farm_root"])

    farms: list[dict[str, Any]] = []
    for p in plan:
        farms.append({
            "farm_idx": p["farm_idx"],
            "farm_root": p["farm_root"],
            "mode": p["mode"],
            "workers": p["workers"],
            "original_seed_base": p["seed_base"],
            "seed_base": p["seed_base"],
            "run_idx": 0,
            "history": [],
            "done": False,
            "done_reason": None,
            "proc": None,
        })

    try:
        for f in farms:
            _spawn_one_run(f, args, out_root)
            print(
                f"[spawn] farm_{f['farm_idx']:02d} run_{f['run_idx']} "
                f"seed=0x{f['seed_base']:08X} sudo_pid={f['proc'].pid}"
            )

        for f in farms:
            ok = wait_for_ready(f, timeout=args.ready_timeout)
            if not ok:
                print(f"[ready] farm_{f['farm_idx']:02d} FAILED (ns_log={f['ns_log']})")
                raise RuntimeError("farm readiness failed")
            print(f"[ready] farm_{f['farm_idx']:02d} ready")

        start_mono = time.monotonic()
        deadline = start_mono + args.wall_clock
        print(
            f"\n[run]  {len(farms)} farms running; wall-clock budget={args.wall_clock}s\n"
        )

        last_tick = 0.0
        while True:
            now = time.monotonic()
            alive = [f for f in farms if not f["done"]]
            if not alive:
                print("[main] all farms done")
                break
            if now >= deadline:
                print("[main] wall-clock deadline reached")
                break

            for f in alive:
                rc = f["proc"].poll()
                if rc is None:
                    continue
                entry = _process_exit(f, rc, args)
                _append_history(f, entry, out_root)
                cls = entry["classification"]
                tag = (
                    f"rc={rc} reason={entry['reason']} "
                    f"attempts={entry['attempts']} elapsed={entry['elapsed']} "
                    f"classification={cls}"
                )
                print(f"[exit] farm_{f['farm_idx']:02d} run_{f['run_idx']} {tag}")
                try:
                    f["log_fh"].close()
                except Exception:
                    pass

                is_new = isinstance(cls, str) and cls.startswith("new:")
                max_runs = args.max_runs_per_farm
                cap_reached = max_runs and (f["run_idx"] + 1) >= max_runs
                remaining = deadline - time.monotonic()

                if is_new:
                    print(f"[NEW ] farm_{f['farm_idx']:02d} NEW CRASH SIGNATURE: {cls}")
                    print(f"[NEW ] preserved at {entry['out_dir']}")
                    f["done"] = True
                    f["done_reason"] = "new_crash"
                elif cap_reached:
                    f["done"] = True
                    f["done_reason"] = "max_runs_reached"
                elif remaining <= 10:
                    f["done"] = True
                    f["done_reason"] = "wall_clock_near"
                else:
                    f["run_idx"] += 1
                    f["seed_base"] = seed_base_for_run(
                        f["original_seed_base"], f["run_idx"], args.restart_seed_stride
                    )
                    _spawn_one_run(f, args, out_root)
                    ok = wait_for_ready(f, timeout=args.ready_timeout)
                    if not ok:
                        print(
                            f"[ready] farm_{f['farm_idx']:02d} run_{f['run_idx']} "
                            f"FAILED after restart; stopping this farm"
                        )
                        f["done"] = True
                        f["done_reason"] = "restart_readiness_failed"
                    else:
                        print(
                            f"[spawn] farm_{f['farm_idx']:02d} run_{f['run_idx']} "
                            f"seed=0x{f['seed_base']:08X} sudo_pid={f['proc'].pid} (restart)"
                        )

            if now - last_tick >= 30:
                alive_after = [f for f in farms if not f["done"]]
                desc = ",".join(
                    f"{f['farm_idx']:02d}:run{f['run_idx']}" for f in alive_after
                )
                print(
                    f"[tick] t+{int(now - start_mono)}s alive=[{desc}] "
                    f"remaining={int(deadline - now)}s"
                )
                last_tick = now
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[int]  keyboard interrupt; stopping farms")
    finally:
        for f in farms:
            if f.get("proc") is not None and f["proc"].poll() is None:
                print(f"[stop] farm_{f['farm_idx']:02d}")
                stop_farm(f)
            try:
                if f.get("log_fh") is not None:
                    f["log_fh"].close()
            except Exception:
                pass

    # Final report
    bucket_counts: dict[str, int] = {}
    new_signatures: list[dict[str, Any]] = []
    farm_reports: list[dict[str, Any]] = []
    for f in farms:
        total_runs = len(f["history"])
        classifications = [h["classification"] for h in f["history"] if h.get("classification")]
        for c in classifications:
            bucket_counts[c] = bucket_counts.get(c, 0) + 1
            if c.startswith("new:"):
                new_signatures.append({
                    "farm_idx": f["farm_idx"],
                    "mode": f["mode"],
                    "classification": c,
                })
        farm_reports.append({
            "farm_idx": f["farm_idx"],
            "mode": f["mode"],
            "total_runs": total_runs,
            "done_reason": f["done_reason"],
            "final_run_idx": f["run_idx"],
            "final_seed_base": f"0x{f['seed_base']:08X}",
            "classifications": classifications,
        })

    final = {
        "out_root": str(out_root),
        "buckets": bucket_counts,
        "new_signatures": new_signatures,
        "farms": farm_reports,
    }
    (out_root / "final_report.json").write_text(json.dumps(final, indent=2) + "\n")

    print(f"\n[done] out_root={out_root}")
    print(f"[done] buckets={bucket_counts}")
    if new_signatures:
        print(f"[done] NEW SIGNATURES ({len(new_signatures)}):")
        for ns in new_signatures:
            print(f"       farm_{ns['farm_idx']:02d} mode={ns['mode']} -> {ns['classification']}")
    else:
        print("[done] no new signatures (all crashes bucketed as known)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
