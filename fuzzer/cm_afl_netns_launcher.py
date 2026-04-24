#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_INIT = HERE / "cm_afl_netns_init.sh"
DEFAULT_MODES = ["net_get_servers", "net_info_version", "net_version"]


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("cm_afl_netns_launcher.py must run as root (use sudo)")


def sh(cmd: list[str], *, check: bool = True, timeout: float | None = None,
       capture: bool = False, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        timeout=timeout,
        text=True,
        capture_output=capture,
        env=env,
    )


def json_write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_farm_root(farm_root: Path) -> None:
    if farm_root.exists():
        sh(["rm", "-rf", str(farm_root)])

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
        (Path("/etc/wibu/CodeMeter"), farm_root / "etc/wibu/CodeMeter"),
        (Path("/var/lib/CodeMeter"), farm_root / "var/lib/CodeMeter"),
        (Path("/var/log/CodeMeter"), farm_root / "var/log/CodeMeter"),
    ]
    for src, dst in copies:
        if not src.exists():
            raise FileNotFoundError(f"missing CodeMeter path: {src}")
        if not any(dst.iterdir()):
            sh(["cp", "-a", f"{src}/.", str(dst)])

    sh([
        "chown", "-R", "daemon:daemon",
        str(farm_root / "work"),
        str(farm_root / "var/tmp/cm_cores"),
    ])


def inst_ranges_for(mode: str) -> str:
    if mode == "net_get_servers":
        return "0x548000-0x889000"
    if mode in {"net_access", "net_access2", "net_version", "net_info_system", "net_info_version"}:
        return "0x564000-0xbf1000"
    raise ValueError(f"unknown mode: {mode}")


def spawn_worker(worker: dict[str, Any], args: argparse.Namespace) -> subprocess.Popen:
    env = os.environ.copy()
    env.update({
        "FARM_ROOT": str(worker["farm_root"]),
        "FARM_HOSTNAME": worker["hostname"],
        "CODEMETER_BIN": str(args.codemeter_bin),
        "AFLPP_ROOT": str(args.aflpp_root),
        "HARNESS_SO": str(ROOT / "preload" / "cm_afl_harness.so"),
        "MODE": worker["mode"],
        "CORPUS_DIR": str(worker["corpus_dir"]),
        "SYNC_DIR": str(worker["sync_dir"]),
        "WORKER_ID": worker["worker_id"],
        "WORKER_ROLE": worker["role"],
        "WORKER_LOG": str(worker["log_path"]),
        "READY_FILE": str(worker["ready_file"]),
        "INST_RANGES": worker["inst_ranges"],
        "TIMEOUT_MS": args.timeout_ms,
        "CPU_CORE": str(worker["cpu_core"]),
    })

    log_fh = worker["ns_log"].open("wb")
    cmd = [
        "unshare",
        "--fork", "--kill-child=SIGINT",
        "--pid", "--mount-proc",
        "--mount", "--ipc", "--net", "--uts",
        "bash", str(args.init_script),
    ]
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=log_fh,
        stderr=log_fh,
        preexec_fn=os.setsid,
    )
    worker["proc"] = proc
    worker["log_fh"] = log_fh
    worker["started_at"] = time.time()
    return proc


def wait_for_ready(worker: dict[str, Any], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if worker["ready_file"].exists():
            return True
        if worker["proc"].poll() is not None:
            return False
        time.sleep(0.5)
    return False


def stop_worker(worker: dict[str, Any], grace: float = 15.0) -> None:
    proc = worker.get("proc")
    if proc is None:
        return
    if proc.poll() is not None:
        try:
            worker["log_fh"].close()
        except Exception:
            pass
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
    try:
        worker["log_fh"].close()
    except Exception:
        pass


def build_assets_and_corpora(args: argparse.Namespace) -> None:
    sh(["bash", str(ROOT / "scripts" / "rebuild_cm_afl_net_assets.sh")], timeout=120)
    sh(["bash", str(ROOT / "scripts" / "build_cm_afl_harness.sh")], timeout=120)
    for mode in args.modes:
        sh(
            ["python3", str(ROOT / "scripts" / "build_cm_afl_net_corpus.py"), mode,
             str(ROOT / "seeds" / f"cm_afl_{mode}")],
            timeout=60,
        )


def build_worker_corpus(mode: str, args: argparse.Namespace, out_root: Path) -> Path:
    source_dir = ROOT / "seeds" / f"cm_afl_{mode}"
    if not args.single_seed_name:
        return source_dir

    seed_path = source_dir / args.single_seed_name
    if not seed_path.is_file():
        raise FileNotFoundError(f"missing seed for {mode}: {seed_path}")

    corpus_dir = out_root / "worker_corpus" / mode
    corpus_dir.mkdir(parents=True, exist_ok=True)
    dst = corpus_dir / args.single_seed_name
    if dst.exists():
        dst.unlink()
    os.link(seed_path, dst)
    return corpus_dir


def make_workers(args: argparse.Namespace, out_root: Path, root_dir: Path) -> list[dict[str, Any]]:
    workers: list[dict[str, Any]] = []
    idx = 0
    cpu_count = os.cpu_count() or 1

    def pick_cpu(slot: int) -> int:
        if cpu_count <= 1:
            return 0
        return 1 + (slot % (cpu_count - 1))

    for mode in args.modes:
        sync_dir = out_root / mode / "sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        chmod_target = out_root / mode
        chmod_target.mkdir(parents=True, exist_ok=True)
        os.chmod(chmod_target, 0o777)

    for slot in range(args.workers_per_mode):
        for mode in args.modes:
            sync_dir = out_root / mode / "sync"
            role = "M" if slot == 0 else "S"
            worker_id = f"{mode}_main" if slot == 0 else f"{mode}_s{slot}"
            farm_root = root_dir / f"worker_{idx:02d}"
            out_dir = out_root / mode / "workers" / worker_id
            out_dir.mkdir(parents=True, exist_ok=True)
            workers.append({
                "idx": idx,
                "mode": mode,
                "role": role,
                "worker_id": worker_id,
                "hostname": f"cmafl{idx:02d}",
                "farm_root": farm_root,
                "sync_dir": sync_dir,
                "corpus_dir": build_worker_corpus(mode, args, out_root),
                "log_path": out_dir / "afl.log",
                "ns_log": out_dir / "namespace.log",
                "ready_file": out_dir / "ready",
                "inst_ranges": inst_ranges_for(mode),
                "cpu_core": pick_cpu(idx),
            })
            idx += 1
    return workers


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run AFL/QEMU network-faithful CodeMeterLin workers in isolated namespaces.")
    ap.add_argument("--modes", nargs="+", default=DEFAULT_MODES)
    ap.add_argument("--workers-per-mode", type=int, default=6)
    ap.add_argument("--root", type=Path, default=Path("/var/tmp/cm_afl_netns"))
    ap.add_argument("--out-root", type=Path, default=None)
    ap.add_argument("--init-script", type=Path, default=DEFAULT_INIT)
    ap.add_argument("--codemeter-bin", type=Path, default=Path("/usr/sbin/CodeMeterLin"))
    ap.add_argument("--aflpp-root", type=Path, default=Path("/home/avj/clones/AFLplusplus"))
    ap.add_argument("--timeout-ms", default="30000+")
    ap.add_argument("--single-seed-name", default=None,
                    help="if set, use only this seed filename from each mode corpus")
    ap.add_argument("--ready-timeout", type=float, default=120.0)
    ap.add_argument("--wall-clock", type=int, default=0,
                    help="seconds to run before stopping; 0 means run until interrupted")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    require_root()

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = args.out_root or Path(f"/home/avj/clones/ax_fuzz/output/cm_afl_netns_{ts}")
    out_root.mkdir(parents=True, exist_ok=True)
    args.root.mkdir(parents=True, exist_ok=True)

    build_assets_and_corpora(args)
    workers = make_workers(args, out_root, args.root)

    try:
        print(f"[plan] modes={args.modes} workers_per_mode={args.workers_per_mode} total={len(workers)}")
        for worker in workers:
            print(
                f"  {worker['worker_id']}: mode={worker['mode']} role={worker['role']} "
                f"cpu={worker['cpu_core']} root={worker['farm_root']}"
            )
            build_farm_root(worker["farm_root"])
            if worker["ready_file"].exists():
                worker["ready_file"].unlink()
            spawn_worker(worker, args)
            if not wait_for_ready(worker, args.ready_timeout):
                raise RuntimeError(f"worker did not become ready: {worker['worker_id']} ({worker['mode']})")
        json_write(out_root / "launcher_config.json", {
            "modes": args.modes,
            "workers_per_mode": args.workers_per_mode,
            "timeout_ms": args.timeout_ms,
            "wall_clock": args.wall_clock,
            "workers": [
                {
                    "worker_id": w["worker_id"],
                    "mode": w["mode"],
                    "role": w["role"],
                    "farm_root": str(w["farm_root"]),
                    "sync_dir": str(w["sync_dir"]),
                    "log_path": str(w["log_path"]),
                    "ns_log": str(w["ns_log"]),
                }
                for w in workers
            ],
        })
        print(f"[run] all workers ready; out_root={out_root}")

        if args.wall_clock > 0:
            deadline = time.monotonic() + args.wall_clock
            while time.monotonic() < deadline:
                for worker in workers:
                    if worker["proc"].poll() is not None:
                        raise RuntimeError(f"worker exited early: {worker['worker_id']} rc={worker['proc'].returncode}")
                time.sleep(5)
            print("[run] wall-clock reached; stopping")
        else:
            while True:
                for worker in workers:
                    if worker["proc"].poll() is not None:
                        raise RuntimeError(f"worker exited early: {worker['worker_id']} rc={worker['proc'].returncode}")
                time.sleep(5)
    except KeyboardInterrupt:
        print("[stop] interrupted; stopping workers")
    finally:
        for worker in workers:
            stop_worker(worker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
