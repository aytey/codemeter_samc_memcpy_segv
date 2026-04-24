#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.search_5e_reply_trigger import (  # noqa: E402
    build_hide_so,
    codemeter_pids,
    kill_all_codemeter,
    start_hidden_daemon,
    start_systemd_codemeter,
    stop_systemd_codemeter,
    wait_for_listener,
)


GDB_SCRIPT = ROOT / "gdb_scripts" / "trace_function_entry.py"
RUN_PROBE = ROOT / "scripts" / "run_cm_sdk_probe.sh"

SENDERS = {
    "access": ["bash", str(RUN_PROBE), "access", "--subsystem", "--local"],
    "access2": ["bash", str(RUN_PROBE), "access2", "--subsystem", "--local"],
    "get_servers": ["bash", str(RUN_PROBE), "get-servers"],
    "access_info_system": ["bash", str(RUN_PROBE), "access-info-system", "--subsystem", "--local"],
    "access2_info_system": ["bash", str(RUN_PROBE), "access2-info-system", "--subsystem", "--local"],
    "access_info_version": ["bash", str(RUN_PROBE), "access-info-version", "--subsystem", "--local"],
    "access2_info_version": ["bash", str(RUN_PROBE), "access2-info-version", "--subsystem", "--local"],
}


def run_gdb(pid: int, off: int, out_json: Path, read_size: int, field_offsets: list[int]) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["TRACE_OUT"] = str(out_json)
    env["TRACE_OFF"] = hex(off)
    env["TRACE_READ_SIZE"] = hex(read_size)
    env["TRACE_FIELD_OFFSETS"] = ",".join(hex(x) for x in field_offsets)
    if os.geteuid() == 0:
        cmd = ["timeout", "--signal=KILL", "12", "gdb", "-q", "-p", str(pid), "-x", str(GDB_SCRIPT)]
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
    cmd = [
        "sudo", "-n", "env",
        f"TRACE_OUT={out_json}",
        f"TRACE_OFF={hex(off)}",
        f"TRACE_READ_SIZE={hex(read_size)}",
        f"TRACE_FIELD_OFFSETS={','.join(hex(x) for x in field_offsets)}",
        "timeout", "--signal=KILL", "12",
        "gdb", "-q", "-p", str(pid), "-x", str(GDB_SCRIPT),
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )


def end_gdb(proc: subprocess.Popen[str], timeout_s: float = 5.0) -> tuple[str, str, int | None]:
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
    return out, err, proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=sorted(SENDERS), required=True)
    ap.add_argument("--off", required=True, type=lambda s: int(s, 0))
    ap.add_argument("--post-wait", type=float, default=1.5)
    ap.add_argument("--read-size", type=lambda s: int(s, 0), default=0x100)
    ap.add_argument("--field-offset", dest="field_offsets", action="append", default=[], type=lambda s: int(s, 0))
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d_%H%M%S")
    tag = f"{args.mode}_{args.off:x}"
    out_dir = Path(args.out_dir) if args.out_dir else Path(f"/tmp/trace_function_entry_{tag}_{stamp}")
    out_dir.mkdir(parents=True, exist_ok=True)

    daemon_log = out_dir / "daemon.log"
    hide_log = out_dir / "hide.log"
    trace_json = out_dir / "trace.json"
    meta_json = out_dir / "meta.json"
    sender_stdout = out_dir / "sender.stdout"
    sender_stderr = out_dir / "sender.stderr"
    gdb_stdout = out_dir / "gdb.stdout"
    gdb_stderr = out_dir / "gdb.stderr"

    build_hide_so()
    stop_systemd_codemeter()
    kill_all_codemeter()

    pid = start_hidden_daemon(daemon_log, hide_log)
    try:
        live_pid = wait_for_listener(22350)
        gdb_proc = run_gdb(live_pid, args.off, trace_json, args.read_size, args.field_offsets)
        time.sleep(0.7)

        sender = subprocess.run(
            SENDERS[args.mode],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=90,
        )
        sender_stdout.write_text(sender.stdout, encoding="utf-8")
        sender_stderr.write_text(sender.stderr, encoding="utf-8")

        time.sleep(args.post_wait)
        g_out, g_err, g_rc = end_gdb(gdb_proc)
        gdb_stdout.write_text(g_out, encoding="utf-8")
        gdb_stderr.write_text(g_err, encoding="utf-8")

        result = json.loads(trace_json.read_text(encoding="ascii")) if trace_json.exists() else {}
        meta = {
            "mode": args.mode,
            "off": hex(args.off),
            "requested_pid": pid,
            "live_pid": live_pid,
            "post_gdb_pids": codemeter_pids(),
            "sender_returncode": sender.returncode,
            "daemon_log": str(daemon_log),
            "hide_log": str(hide_log),
            "trace_json": str(trace_json),
            "gdb_stdout": str(gdb_stdout),
            "gdb_stderr": str(gdb_stderr),
            "sender_stdout": str(sender_stdout),
            "sender_stderr": str(sender_stderr),
            "gdb_returncode": g_rc,
            "hit": bool(result),
        }
        meta_json.write_text(json.dumps(meta, indent=2) + "\n", encoding="ascii")
        print(str(trace_json))
        return 0
    finally:
        kill_all_codemeter()
        start_systemd_codemeter()


if __name__ == "__main__":
    raise SystemExit(main())
