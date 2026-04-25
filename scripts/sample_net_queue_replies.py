#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUN_ROOT = Path("/home/avj/clones/ax_fuzz/output/cm_afl_netns_weekend6_20260425_013414")
DEFAULT_MODES = [
    "net_access",
    "net_access2",
    "net_version",
    "net_info_system",
    "net_info_version",
    "net_get_servers",
]
REPLY_RE = re.compile(r"net reply\[(\d+)\] decrypted len=(\d+)")


def sh(cmd: list[str], *, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        timeout=timeout,
        text=True,
        capture_output=True,
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("sample_net_queue_replies.py must run as root (use sudo -n)")


def build_farm_root(farm_root: Path) -> None:
    if farm_root.exists():
        shutil.rmtree(farm_root)

    for rel in [
        "etc/wibu/CodeMeter",
        "var/lib/CodeMeter",
        "var/log/CodeMeter",
        "run/lock",
        "var/tmp/cm_cores",
        "work",
    ]:
        (farm_root / rel).mkdir(parents=True, exist_ok=True)

    for src, dst in [
        (Path("/etc/wibu/CodeMeter"), farm_root / "etc/wibu/CodeMeter"),
        (Path("/var/lib/CodeMeter"), farm_root / "var/lib/CodeMeter"),
        (Path("/var/log/CodeMeter"), farm_root / "var/log/CodeMeter"),
    ]:
        if not src.exists():
            raise FileNotFoundError(f"missing CodeMeter path: {src}")
        sh(["cp", "-a", f"{src}/.", str(dst)])

    sh(
        [
            "chown",
            "-R",
            "daemon:daemon",
            str(farm_root / "work"),
            str(farm_root / "var/tmp/cm_cores"),
            str(farm_root / "var/lib/CodeMeter"),
            str(farm_root / "var/log/CodeMeter"),
        ]
    )


def choose_samples(mode_root: Path, count: int, seed: int, include_base: bool) -> list[Path]:
    queue_paths = sorted(
        p for p in mode_root.glob("sync/*/queue/id:*")
        if p.is_file() and "/.state/" not in str(p)
    )
    if not queue_paths:
        return []

    base = [p for p in queue_paths if "orig:base.bin" in p.name]
    rest = [p for p in queue_paths if p not in base]
    rng = random.Random(f"{seed}:{mode_root.name}")
    rng.shuffle(rest)

    picked: list[Path] = []
    if include_base and base:
        picked.append(base[0])
    need = max(0, count - len(picked))
    picked.extend(rest[:need])
    return picked


def classify_result(rc: int | None, timed_out: bool, stderr: str) -> str:
    if timed_out:
        return "no_reply_or_timeout"
    if rc is None:
        return "infra_error"
    if rc == 139 or rc == -11:
        return "crash"
    if "Segmentation fault" in stderr:
        return "crash"
    if "net reply[" in stderr:
        return "structured_reply"
    if rc == 0:
        return "no_reply_or_timeout"
    return "infra_error"


def replay_one(mode: str, testcase: Path, timeout_s: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cm_queue_probe_", dir="/var/tmp") as tmp:
        tmpdir = Path(tmp)
        farm_root = tmpdir / "farm"
        build_farm_root(farm_root)

        env = os.environ.copy()
        env.update(
            {
                "FARM_ROOT": str(farm_root),
                "HARNESS_SO": str(ROOT / "preload" / "cm_afl_harness.so"),
                "MODE": mode,
                "INPUT": str(testcase),
            }
        )

        inner = r"""
set -euo pipefail
hostname cmprobe || true
mount --make-rprivate /
mount --bind "$FARM_ROOT/etc/wibu/CodeMeter" /etc/wibu/CodeMeter
mount --bind "$FARM_ROOT/var/lib/CodeMeter" /var/lib/CodeMeter
mount --bind "$FARM_ROOT/var/log/CodeMeter" /var/log/CodeMeter
mount --bind "$FARM_ROOT/run/lock" /run/lock
mount --bind "$FARM_ROOT/var/tmp/cm_cores" /var/tmp/cm_cores
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
ip link set lo up
cd "$FARM_ROOT/work"
exec setpriv --reuid daemon --regid daemon --init-groups \
  env \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/var/lib/CodeMeter \
    USER=daemon \
    LOGNAME=daemon \
    LD_PRELOAD="$HARNESS_SO" \
    CM_AFL_HARNESS_MODE="$MODE" \
    CM_AFL_NET_TRANSPORT=tcp \
    AFL_NO_FORKSRV=1 \
    CM_AFL_VERBOSE=1 \
    /usr/sbin/CodeMeterLin "$INPUT"
"""
        cmd = [
            "unshare",
            "--fork",
            "--kill-child=SIGKILL",
            "--pid",
            "--mount-proc",
            "--mount",
            "--ipc",
            "--net",
            "--uts",
            "bash",
            "-lc",
            inner,
        ]

        timed_out = False
        rc: int | None = None
        stdout = ""
        stderr = ""
        try:
            cp = subprocess.run(
                cmd,
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout_s,
            )
            rc = cp.returncode
            stdout = cp.stdout
            stderr = cp.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

        reply_lens = [int(m.group(2)) for m in REPLY_RE.finditer(stderr)]
        bucket = classify_result(rc, timed_out, stderr)
        worker = testcase.parts[-3] if len(testcase.parts) >= 3 else ""
        return {
            "mode": mode,
            "worker": worker,
            "path": str(testcase),
            "name": testcase.name,
            "cov": "+cov" in testcase.name,
            "bucket": bucket,
            "timed_out": timed_out,
            "rc": rc,
            "reply_count": len(reply_lens),
            "reply_lens": reply_lens,
            "stderr_tail": stderr.strip().splitlines()[-12:],
            "stdout_tail": stdout.strip().splitlines()[-12:],
        }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    overall = Counter(r["bucket"] for r in results)
    per_mode: dict[str, Any] = {}
    for mode in sorted({r["mode"] for r in results}):
        rows = [r for r in results if r["mode"] == mode]
        ctr = Counter(r["bucket"] for r in rows)
        per_mode[mode] = {
            "sampled": len(rows),
            "structured_reply": ctr.get("structured_reply", 0),
            "no_reply_or_timeout": ctr.get("no_reply_or_timeout", 0),
            "crash": ctr.get("crash", 0),
            "infra_error": ctr.get("infra_error", 0),
            "reply_rate": (ctr.get("structured_reply", 0) / len(rows)) if rows else 0.0,
            "rows": rows,
        }
    return {
        "sampled": len(results),
        "structured_reply": overall.get("structured_reply", 0),
        "no_reply_or_timeout": overall.get("no_reply_or_timeout", 0),
        "crash": overall.get("crash", 0),
        "infra_error": overall.get("infra_error", 0),
        "reply_rate": (overall.get("structured_reply", 0) / len(results)) if results else 0.0,
        "per_mode": per_mode,
    }


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Sample current net AFL queue entries with isolated one-off replays.")
    ap.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    ap.add_argument("--modes", nargs="+", default=DEFAULT_MODES)
    ap.add_argument("--samples-per-mode", type=int, default=6)
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--timeout-sec", type=float, default=45.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--include-base", action="store_true", default=True)
    ap.add_argument("--no-include-base", dest="include_base", action="store_false")
    ap.add_argument("--out", type=Path, default=None)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    require_root()
    if not args.run_root.is_dir():
        raise SystemExit(f"missing run root: {args.run_root}")

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out or Path(f"/tmp/cm_net_queue_sample_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    selected: list[tuple[str, Path]] = []
    selection: dict[str, list[str]] = {}
    for mode in args.modes:
        mode_root = args.run_root / mode
        paths = choose_samples(mode_root, args.samples_per_mode, args.seed, args.include_base)
        selection[mode] = [str(p) for p in paths]
        for path in paths:
            selected.append((mode, path))

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as exe:
        future_map = {
            exe.submit(replay_one, mode, path, args.timeout_sec): (mode, path)
            for mode, path in selected
        }
        for fut in concurrent.futures.as_completed(future_map):
            mode, path = future_map[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                results.append(
                    {
                        "mode": mode,
                        "worker": "",
                        "path": str(path),
                        "name": path.name,
                        "cov": "+cov" in path.name,
                        "bucket": "infra_error",
                        "timed_out": False,
                        "rc": None,
                        "reply_count": 0,
                        "reply_lens": [],
                        "stderr_tail": [f"exception: {exc}"],
                        "stdout_tail": [],
                    }
                )

    summary = summarize(results)
    payload = {
        "run_root": str(args.run_root),
        "samples_per_mode": args.samples_per_mode,
        "parallel": args.parallel,
        "timeout_sec": args.timeout_sec,
        "selection": selection,
        "summary": summary,
    }
    out_path = out_dir / "summary.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(out_path)
    for mode in args.modes:
        row = summary["per_mode"].get(mode)
        if not row:
            print(f"{mode:16} sampled=0")
            continue
        print(
            f"{mode:16} sampled={row['sampled']:2d} "
            f"reply={row['structured_reply']:2d} "
            f"no_reply={row['no_reply_or_timeout']:2d} "
            f"crash={row['crash']:2d} "
            f"infra={row['infra_error']:2d}"
        )
    print(
        f"overall           sampled={summary['sampled']:2d} "
        f"reply={summary['structured_reply']:2d} "
        f"no_reply={summary['no_reply_or_timeout']:2d} "
        f"crash={summary['crash']:2d} "
        f"infra={summary['infra_error']:2d}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
