#!/usr/bin/env python3
"""Run local CodeMeterLin fuzz farms over veth-backed network namespaces.

The original fuzz_farm_launcher.py runs the fuzzer inside the same network
namespace as CodeMeterLin and talks to 127.0.0.1.  This launcher keeps each
CodeMeterLin in its own target netns, but runs the fuzz workers on the host and
connects to the target namespace IP over a veth pair.  From the daemon's point
of view the SAMC peer is a non-loopback address, so this exercises the
"remote-looking" listener path without using a production remote host.

Each target namespace also gets a default route through the host-side veth.  By
default the launcher installs one nftables masquerade rule for the namespace
CIDR, so outbound traffic from namespaced daemons can reach the LAN if the
CodeMeter configuration tries to do that.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import ipaddress
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_INIT_SCRIPT = HERE / "samc_veth_target_init.sh"
DEFAULT_SUPERVISOR = HERE / "samc_light_supervisor.py"
DEFAULT_PREFIXED_HELLO_REPRO = HERE / "repro_prefixed_hello_standalone.py"
DEFAULT_ECDH_PREFIX_SUPERVISOR = HERE / "samc_ecdh_prefix_supervisor.py"
DEFAULT_DS_SUPERVISOR = HERE / "samc_ds_supervisor.py"
DEFAULT_DS_HELPER_DIR = Path("/home/avj/clones/ax_decrypt/009/research_scripts")
DEFAULT_MODES = ["mixed", "hello", "ack", "big", "sweep", "mixed"]

# Signature bucketing — first CodeMeterLin-relative frame offset.
# Seeded with the crash this repo was created to reproduce.
KNOWN_SIGNATURES: dict[str, str] = {
    "CodeMeterLin+0x8f431d": "memcpy_8f431d_prefixed_hello",
}

TOOL_FALLBACKS = {
    "ip": ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
    "nft": ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"],
    "sysctl": ["/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl", "/bin/sysctl"],
    "ss": ["/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss", "/bin/ss"],
}


def tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for path in TOOL_FALLBACKS.get(name, []):
        if Path(path).exists():
            return path
    raise FileNotFoundError(f"required tool not found: {name}")


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


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("samc_veth_farm_launcher.py must run as root (use sudo)")


def load_light_supervisor(path: Path):
    spec = importlib.util.spec_from_file_location("samc_light_supervisor_imported", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_farm_root(farm_root: Path) -> None:
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
            raise FileNotFoundError(f"source CodeMeter state path missing: {src}")
        if not any(dst.iterdir()):
            sh(["cp", "-a", f"{src}/.", str(dst)])

    sh([
        "chown", "-R", "daemon:daemon",
        str(farm_root / "work"),
        str(farm_root / "var/tmp/cm_cores"),
    ])


def netns_exists(name: str) -> bool:
    out = sh([tool("ip"), "netns", "list"], capture=True).stdout
    return any(line.split()[0] == name for line in out.splitlines() if line.strip())


def link_exists(name: str) -> bool:
    return sh([tool("ip"), "link", "show", "dev", name],
              check=False, capture=True).returncode == 0


def delete_netns(name: str) -> None:
    if netns_exists(name):
        sh([tool("ip"), "netns", "del", name], check=False, capture=True)


def delete_link(name: str) -> None:
    if link_exists(name):
        sh([tool("ip"), "link", "del", name], check=False)


def allocate_farm_net(cidr: str, farm_idx: int) -> dict[str, str]:
    base = ipaddress.ip_network(cidr, strict=False)
    if base.version != 4:
        raise ValueError("--netns-cidr must be IPv4")
    step = 4
    network_addr = int(base.network_address) + farm_idx * step
    net = ipaddress.ip_network(f"{ipaddress.ip_address(network_addr)}/30", strict=False)
    if not net.subnet_of(base):
        raise ValueError(f"farm {farm_idx} /30 allocation is outside {base}")
    hosts = list(net.hosts())
    if len(hosts) != 2:
        raise AssertionError(net)
    return {
        "network": str(net),
        "host_ip": str(hosts[0]),
        "target_ip": str(hosts[1]),
        "prefix": "30",
    }


def default_route_iface() -> str:
    out = sh([tool("ip"), "route", "show", "default"], capture=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("could not determine default route interface")


def setup_nft_nat(table: str, source_cidr: str, out_iface: str) -> None:
    nft = tool("nft")
    sh([nft, "add", "table", "ip", table])
    sh([
        nft, "add", "chain", "ip", table, "postrouting",
        "{", "type", "nat", "hook", "postrouting", "priority", "srcnat",
        ";", "policy", "accept", ";", "}",
    ])
    sh([
        nft, "add", "rule", "ip", table, "postrouting",
        "ip", "saddr", source_cidr,
        "oifname", out_iface,
        "masquerade",
    ])


def cleanup_nft_nat(table: str | None) -> None:
    if not table:
        return
    try:
        sh([tool("nft"), "delete", "table", "ip", table], check=False)
    except FileNotFoundError:
        pass


def setup_netns(farm: dict[str, Any], *, replace_existing: bool) -> None:
    ip = tool("ip")
    ns = farm["netns"]
    host_if = farm["host_if"]
    target_if = farm["target_if"]
    host_ip = farm["host_ip"]
    target_ip = farm["target_ip"]
    prefix = farm["prefix"]

    if netns_exists(ns):
        if not replace_existing:
            raise RuntimeError(f"netns already exists: {ns} (use --replace-existing)")
        delete_netns(ns)
    delete_link(host_if)

    sh([ip, "netns", "add", ns])
    sh([ip, "link", "add", host_if, "type", "veth", "peer", "name", target_if])
    sh([ip, "link", "set", target_if, "netns", ns])
    sh([ip, "addr", "add", f"{host_ip}/{prefix}", "dev", host_if])
    sh([ip, "link", "set", host_if, "up"])
    sh([ip, "netns", "exec", ns, "ip", "addr", "add", f"{target_ip}/{prefix}", "dev", target_if])
    sh([ip, "netns", "exec", ns, "ip", "link", "set", target_if, "up"])
    sh([ip, "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
    sh([ip, "netns", "exec", ns, "ip", "route", "replace", "default", "via", host_ip])


def cleanup_netns(farm: dict[str, Any]) -> None:
    try:
        delete_netns(farm["netns"])
    finally:
        delete_link(farm["host_if"])


def spawn_target(farm: dict[str, Any], args: argparse.Namespace) -> subprocess.Popen:
    out_dir = farm["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    # The target init mounts a private tmpfs over /tmp. Keep control files
    # under FARM_ROOT/work so they are visible both inside the mount namespace
    # and from the host, even when --out-root is below /tmp.
    ready_file = farm["farm_root"] / "work" / "ready"
    if ready_file.exists():
        ready_file.unlink()
    ns_log = out_dir / "namespace_target.log"
    daemon_log = farm["farm_root"] / "work" / "daemon.log"
    if daemon_log.exists():
        daemon_log.unlink()
    log_fh = ns_log.open("wb")

    env = os.environ.copy()
    env.update({
        "FARM_ROOT": str(farm["farm_root"]),
        "FARM_HOSTNAME": f"cmveth{farm['farm_idx']:02d}",
        "CODEMETER_BIN": str(args.codemeter_bin),
        "PORT": str(args.port),
        "READY_FILE": str(ready_file),
        "DAEMON_LOG": str(daemon_log),
    })
    cmd = [
        tool("ip"), "netns", "exec", farm["netns"],
        "unshare",
        "--fork", "--kill-child=SIGINT",
        "--pid", "--mount-proc",
        "--mount", "--ipc", "--uts",
        "bash", str(args.init_script),
    ]
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=log_fh,
        stderr=log_fh,
        preexec_fn=os.setsid,
    )
    farm["target_log_fh"] = log_fh
    farm["ready_file"] = ready_file
    farm["ns_log"] = ns_log
    farm["daemon_log"] = daemon_log
    farm["target_proc"] = proc
    return proc


def stop_process_group(proc: subprocess.Popen | None, *, grace: float = 10.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
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


def wait_for_ready(farm: dict[str, Any], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if farm["ready_file"].exists():
            return True
        if farm["target_proc"].poll() is not None:
            return False
        time.sleep(0.25)
    return False


def netns_listener_ready(netns: str, port: int) -> bool:
    try:
        out = sh(
            [tool("ip"), "netns", "exec", netns, "ss", "-tln", f"( sport = :{port} )"],
            capture=True,
            timeout=2.0,
        ).stdout
    except Exception:
        return False
    return f":{port}" in out


def tcp_reachable(host: str, port: int, timeout: float = 0.5) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def newest_core_in(root: Path) -> dict[str, Any] | None:
    newest: tuple[int, Path] | None = None
    if not root.exists():
        return None
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
    cur_core: dict[str, Any] | None,
    start_wall: float,
) -> bool:
    return (
        cur_core is not None and
        (baseline_core is None or
         cur_core["path"] != baseline_core["path"] or
         cur_core["mtime_ns"] != baseline_core["mtime_ns"]) and
        cur_core["mtime_ns"] >= int(start_wall * 1_000_000_000)
    )


def run_prefixed_hello_canary(farm: dict[str, Any], args: argparse.Namespace) -> None:
    """Run the updated standalone remote/ECDH prefixed-HELLO repro once.

    This is a ground-truth check for the veth farm: if the target namespace can
    be crashed by the known ECDH-channel HELLO trigger, the farm's target
    reachability and crash oracle are wired correctly.
    """
    out_dir = farm["out_dir"]
    log_path = out_dir / "prefixed_hello_canary.log"
    baseline_core = newest_core_in(farm["core_dir"])
    start_wall = time.time()
    start_mono = time.monotonic()
    cmd = [
        sys.executable,
        str(args.prefixed_hello_repro),
        "--host", farm["target_ip"],
        "--port", str(args.port),
        "--channel", "ecdh",
        "--connect-timeout", str(args.canary_connect_timeout),
        "--socket-timeout", str(args.canary_socket_timeout),
        "--wait", "0",
        "--no-crash-oracle",
    ]
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=args.canary_process_timeout,
            check=False,
        )

    deadline = time.monotonic() + args.canary_wait
    target_rc = farm["target_proc"].poll()
    cur_core = newest_core_in(farm["core_dir"])
    listener_down = not netns_listener_ready(farm["netns"], args.port)
    changed_core = core_changed_since(baseline_core, cur_core, start_wall)
    while time.monotonic() < deadline:
        target_rc = farm["target_proc"].poll()
        cur_core = newest_core_in(farm["core_dir"])
        listener_down = not netns_listener_ready(farm["netns"], args.port)
        changed_core = core_changed_since(baseline_core, cur_core, start_wall)
        if target_rc is not None or changed_core or listener_down:
            break
        time.sleep(0.25)

    result = {
        "reason": "crash_or_restart" if (
            target_rc is not None or changed_core or listener_down
        ) else "no_crash_observed",
        "elapsed": time.monotonic() - start_mono,
        "repro_rc": proc.returncode,
        "repro_log": str(log_path),
        "target_rc": target_rc,
        "baseline_core": baseline_core,
        "core": cur_core,
        "core_changed": changed_core,
        "listener_down": listener_down,
        "command": cmd,
    }
    json_write(out_dir / "summary.json", {
        "result": result,
        "attempts": 1,
        "per_worker_attempts": [],
        "worker_pids": [],
        "worker_exitcodes": [],
        "target_proc_pid": farm["target_proc"].pid,
        "target_proc_rc": farm["target_proc"].poll(),
        "baseline_core": baseline_core,
        "end_core": newest_core_in(farm["core_dir"]),
        "netns": farm["netns"],
        "network": farm["network"],
        "host_ip": farm["host_ip"],
        "target_ip": farm["target_ip"],
        "crash_attribution_count": 1 if result["reason"] == "crash_or_restart" else 0,
    })
    json_write(out_dir / "prefixed_hello_canary.json", result)


def is_ecdh_prefix_mode(mode: str) -> bool:
    return mode in {"ecdh_prefix_hello", "ecdh_prefix_ack", "ecdh_prefix_mixed"}


def ecdh_prefix_inner_mode(mode: str) -> str:
    if mode == "ecdh_prefix_hello":
        return "hello"
    if mode == "ecdh_prefix_ack":
        return "ack"
    if mode == "ecdh_prefix_mixed":
        return "mixed"
    raise AssertionError(mode)


def is_ds_mode(mode: str) -> bool:
    return mode in {
        "ds_auth0021", "ds_init0511", "ds_query0031",
        "ds_cmd00f1_5a", "ds_cmd00f1_69", "ds_mixed",
    }


def ds_inner_mode(mode: str) -> str:
    return mode[len("ds_"):]  # strip "ds_" prefix


def configure_sweep(light, args: argparse.Namespace, config: dict[str, Any],
                    workers: int, mode: str) -> dict[str, Any]:
    if mode != "sweep":
        return {}
    all_opcodes = light._parse_opcode_spec(args.sweep_opcodes)
    skip = set(light._parse_opcode_spec(args.sweep_skip_opcodes)) if args.sweep_skip_opcodes else set()
    all_opcodes = [op for op in all_opcodes if op not in skip]
    if not all_opcodes:
        raise SystemExit("--sweep-opcodes/--sweep-skip-opcodes resolved to an empty set")
    opcodes_per_worker = {w: all_opcodes[w::workers] for w in range(workers)}
    config["sweep_opcodes_per_worker"] = opcodes_per_worker
    config["sweep_body_len"] = args.sweep_body_len
    config["sweep_body_seed"] = args.sweep_body_seed
    config["sweep_skip_opcodes"] = sorted(skip)
    config["sweep_prefix_zero_bytes"] = args.sweep_prefix_zero_bytes
    config["sweep_patch_sid"] = bool(args.sweep_patch_sid)
    if args.sweep_body_lengths:
        config["sweep_body_lengths"] = [int(x, 0) for x in args.sweep_body_lengths.split(",") if x.strip()]
    else:
        config["sweep_body_lengths"] = []
    return {
        "opcode_spec": args.sweep_opcodes,
        "skip_spec": args.sweep_skip_opcodes,
        "skip_resolved": sorted(skip),
        "body_len": args.sweep_body_len,
        "body_seed": args.sweep_body_seed,
        "body_lengths": config["sweep_body_lengths"],
        "prefix_zero_bytes": args.sweep_prefix_zero_bytes,
        "patch_sid": bool(args.sweep_patch_sid),
        "opcodes_per_worker": {str(k): v for k, v in opcodes_per_worker.items()},
    }


def start_farm_workers(farm: dict[str, Any], light, args: argparse.Namespace) -> None:
    mode = farm["mode"]
    roles = light.roles_for(args.workers_per_farm, mode)
    seeds = [farm["seed_base"] + i for i in range(args.workers_per_farm)]
    out_dir = farm["out_dir"]
    config: dict[str, Any] = {
        "ax_fuzz": str(Path(args.ax_fuzz).resolve()),
        "out_dir": str(out_dir),
        "host": farm["target_ip"],
        "port": args.port,
        "iterations": args.iterations,
        "ring_size": args.ring_size,
        "mode": mode,
    }
    sweep_meta = configure_sweep(light, args, config, args.workers_per_farm, mode)

    ctx = mp.get_context("fork")
    stop_event = ctx.Event()
    counters = [ctx.Value("Q", 0, lock=False) for _ in range(args.workers_per_farm)]
    procs = []
    for worker_id, (seed, role) in enumerate(zip(seeds, roles)):
        proc = ctx.Process(
            target=light.worker_main,
            args=(config, worker_id, seed, role, stop_event, counters[worker_id]),
            name=f"samc-veth-farm{farm['farm_idx']:02d}-worker{worker_id:02d}",
        )
        proc.start()
        procs.append(proc)

    farm["stop_event"] = stop_event
    farm["worker_procs"] = procs
    farm["counters"] = counters
    farm["roles"] = roles
    farm["seeds"] = seeds
    farm["baseline_core"] = newest_core_in(farm["core_dir"])
    farm["start_wall"] = time.time()
    farm["start_mono"] = time.monotonic()
    run_config = {
        "farm_idx": farm["farm_idx"],
        "netns": farm["netns"],
        "network": farm["network"],
        "host_ip": farm["host_ip"],
        "target_ip": farm["target_ip"],
        "port": args.port,
        "mode": mode,
        "workers": args.workers_per_farm,
        "roles": roles,
        "seeds": seeds,
        "baseline_core": farm["baseline_core"],
        "start_wall": farm["start_wall"],
        "config": {k: v for k, v in config.items() if k != "sweep_opcodes_per_worker"},
    }
    if sweep_meta:
        run_config["sweep"] = sweep_meta
    json_write(out_dir / "run_config.json", run_config)


def start_ecdh_prefix_supervisor(farm: dict[str, Any], args: argparse.Namespace) -> None:
    out_dir = farm["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "ecdh_prefix_supervisor.log"
    cmd = [
        sys.executable,
        str(args.ecdh_prefix_supervisor),
        "--host", farm["target_ip"],
        "--port", str(args.port),
        "--out-dir", str(out_dir),
        "--mode", ecdh_prefix_inner_mode(farm["mode"]),
        "--workers", str(args.workers_per_farm),
        "--iterations", str(args.iterations),
        "--ring-size", str(args.ring_size),
        "--seed-base", f"0x{farm['seed_base']:08X}",
        "--timeout", str(args.timeout),
        "--connect-timeout", str(args.ecdh_prefix_connect_timeout),
        "--socket-timeout", str(args.ecdh_prefix_socket_timeout),
        "--opcodes", args.ecdh_prefix_opcodes,
        "--skip-opcodes", args.ecdh_prefix_skip_opcodes,
        "--prefix-lengths", args.ecdh_prefix_lengths,
        "--known-prefix", args.ecdh_prefix_known,
        "--include-known-every", str(args.ecdh_prefix_include_known_every),
        "--ax-fuzz", str(args.ax_fuzz),
        "--repro", str(args.prefixed_hello_repro),
        "--core-dir", str(farm["core_dir"]),
    ]
    log_fh = log_path.open("wb")
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=log_fh,
        preexec_fn=os.setsid,
    )
    farm["prefix_proc"] = proc
    farm["prefix_log_fh"] = log_fh
    farm["prefix_log"] = log_path
    farm["baseline_core"] = newest_core_in(farm["core_dir"])
    farm["start_wall"] = time.time()
    farm["start_mono"] = time.monotonic()
    json_write(out_dir / "veth_prefix_launcher.json", {
        "farm_idx": farm["farm_idx"],
        "netns": farm["netns"],
        "network": farm["network"],
        "host_ip": farm["host_ip"],
        "target_ip": farm["target_ip"],
        "mode": farm["mode"],
        "command": cmd,
        "log": str(log_path),
        "baseline_core": farm["baseline_core"],
        "start_wall": farm["start_wall"],
    })


def start_ds_supervisor(farm: dict[str, Any], args: argparse.Namespace) -> None:
    out_dir = farm["out_dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "ds_supervisor.log"
    cmd = [
        sys.executable,
        str(args.ds_supervisor),
        "--host", farm["target_ip"],
        "--port", str(args.port),
        "--out-dir", str(out_dir),
        "--mode", ds_inner_mode(farm["mode"]),
        "--workers", str(args.workers_per_farm),
        "--iterations", str(args.iterations),
        "--ring-size", str(args.ring_size),
        "--seed-base", f"0x{farm['seed_base']:08X}",
        "--timeout", str(args.timeout),
        "--connect-timeout", str(args.ds_connect_timeout),
        "--socket-timeout", str(args.ds_socket_timeout),
        "--helper-dir", str(args.ds_helper_dir),
        "--core-dir", str(farm["core_dir"]),
    ]
    log_fh = log_path.open("wb")
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=log_fh,
        preexec_fn=os.setsid,
    )
    farm["prefix_proc"] = proc
    farm["prefix_log_fh"] = log_fh
    farm["prefix_log"] = log_path
    farm["baseline_core"] = newest_core_in(farm["core_dir"])
    farm["start_wall"] = time.time()
    farm["start_mono"] = time.monotonic()
    json_write(out_dir / "veth_ds_launcher.json", {
        "farm_idx": farm["farm_idx"],
        "netns": farm["netns"],
        "network": farm["network"],
        "host_ip": farm["host_ip"],
        "target_ip": farm["target_ip"],
        "mode": farm["mode"],
        "command": cmd,
        "log": str(log_path),
        "baseline_core": farm["baseline_core"],
        "start_wall": farm["start_wall"],
    })


def stop_farm_workers(farm: dict[str, Any], *, join_timeout: float) -> None:
    stop_event = farm.get("stop_event")
    if stop_event is not None:
        stop_event.set()
    for proc in farm.get("worker_procs", []):
        proc.join(timeout=join_timeout)
    for proc in farm.get("worker_procs", []):
        if proc.is_alive():
            proc.terminate()
    for proc in farm.get("worker_procs", []):
        proc.join(timeout=2.0)
    for proc in farm.get("worker_procs", []):
        if proc.is_alive():
            proc.kill()


def write_farm_summary(farm: dict[str, Any], light, result: dict[str, Any]) -> None:
    counts = [c.value for c in farm.get("counters", [])]
    try:
        attribution = light.write_crash_attribution(farm["out_dir"])
    except Exception as exc:
        attribution = {"error": f"{type(exc).__name__}:{exc}", "count": 0}
    summary = {
        "result": result,
        "attempts": sum(counts),
        "per_worker_attempts": counts,
        "worker_pids": [p.pid for p in farm.get("worker_procs", [])],
        "worker_exitcodes": [p.exitcode for p in farm.get("worker_procs", [])],
        "target_proc_pid": farm["target_proc"].pid,
        "target_proc_rc": farm["target_proc"].poll(),
        "baseline_core": farm.get("baseline_core"),
        "end_core": newest_core_in(farm["core_dir"]),
        "netns": farm["netns"],
        "network": farm["network"],
        "host_ip": farm["host_ip"],
        "target_ip": farm["target_ip"],
        "crash_attribution_count": attribution.get("count"),
    }
    json_write(farm["out_dir"] / "summary.json", summary)


def _out_dir_for_run(out_root: Path, farm_idx: int, run_idx: int) -> Path:
    return out_root / f"farm_{farm_idx:02d}" / f"run_{run_idx}"


def _append_farm_history(farm: dict[str, Any], entry: dict[str, Any]) -> None:
    farm["history"].append(entry)
    hist_path = Path(farm["out_root"]) / f"farm_{farm['farm_idx']:02d}" / "history.jsonl"
    hist_path.parent.mkdir(parents=True, exist_ok=True)
    with hist_path.open("a", encoding="utf-8") as hf:
        hf.write(json.dumps(entry, sort_keys=True) + "\n")


def extract_signature(core_path: Path, binary: Path,
                      n_frames: int = 8, timeout: float = 60.0) -> dict[str, Any]:
    """Run gdb on a core and return binary-relative frame offsets as a signature."""
    try:
        out = subprocess.run(
            ["gdb", "-batch", "-nx", "-q", str(binary), str(core_path),
             "-ex", "info proc mappings",
             "-ex", f"bt {n_frames}"],
            check=False, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "gdb_timeout", "frames": [], "base": None}
    except FileNotFoundError:
        return {"error": "gdb_not_found", "frames": [], "base": None}

    text = (out.stdout or "") + "\n" + (out.stderr or "")
    base: int | None = None
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
    for f in sig.get("frames", []):
        if f.startswith("CodeMeterLin+"):
            return KNOWN_SIGNATURES.get(f, f"new:{f}")
    return "unknown_no_binary_frame"


def _process_run_core(farm: dict[str, Any], cur_core: dict[str, Any],
                      args: argparse.Namespace) -> dict[str, Any]:
    """Classify the core for this run and apply the exemplar-per-signature policy.

    Returns a dict of core metadata to merge into the history entry.
    The core path inside the namespace is mapped back to the host-side path
    via farm_root/var/tmp/cm_cores/<basename>.  The first core per (farm,
    signature) is kept; subsequent identical signatures are deleted to prevent
    disk exhaustion during long restart campaigns (~800 MB per core).
    --keep-known-cores overrides the deletion of known-signature cores.
    """
    in_ns = Path(cur_core["path"])
    host_core = farm["core_dir"] / in_ns.name
    result: dict[str, Any] = {
        "core_path_ns": str(in_ns),
        "core_path_host": str(host_core),
        "core_size": cur_core.get("size"),
    }
    if not host_core.exists():
        result["classification"] = "core_missing"
        return result

    sig = extract_signature(host_core, args.codemeter_bin)
    cls = classify_signature(sig)
    result["signature"] = sig
    result["classification"] = cls

    is_known = cls in KNOWN_SIGNATURES.values()
    first_seen: dict[str, str] = farm.setdefault("first_core_per_sig", {})
    keep = False
    if args.keep_known_cores and is_known:
        keep = True
        result["core_kept_reason"] = "keep_known_cores"
    elif cls not in first_seen:
        keep = True
        first_seen[cls] = str(host_core)
        result["core_kept_reason"] = (
            "first_exemplar_known" if is_known else "first_exemplar_new"
        )
    if not keep:
        try:
            host_core.unlink()
            result["core_deleted"] = True
        except OSError as exc:
            result["core_delete_error"] = f"{type(exc).__name__}:{exc}"
    return result


def make_plan(args: argparse.Namespace, out_root: Path) -> list[dict[str, Any]]:
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if not modes:
        raise SystemExit("--modes resolved to an empty list")
    plan = []
    for idx in range(args.farms):
        net = allocate_farm_net(args.netns_cidr, idx + args.netns_offset)
        netns = f"{args.netns_prefix}{idx:02d}"
        host_if = f"cmvh{idx:03d}"
        target_if = f"cmvn{idx:03d}"
        if len(host_if) > 15 or len(target_if) > 15:
            raise SystemExit("generated veth interface name exceeds Linux IFNAMSIZ")
        farm_root = args.root / f"farm_{idx:02d}"
        seed = args.seed_base_origin + idx * args.seed_base_stride
        plan.append({
            "farm_idx": idx,
            "farm_root": farm_root,
            "out_dir": out_root / f"farm_{idx:02d}" / "run_0",
            "out_root": out_root,
            "core_dir": farm_root / "var/tmp/cm_cores",
            "netns": netns,
            "host_if": host_if,
            "target_if": target_if,
            "network": net["network"],
            "host_ip": net["host_ip"],
            "target_ip": net["target_ip"],
            "prefix": net["prefix"],
            "mode": modes[idx % len(modes)],
            "seed_base": seed,
            "original_seed_base": seed,
            "run_idx": 0,
            "history": [],
            "done": False,
            "done_reason": None,
        })
    return plan


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Launch local CodeMeterLin targets in veth netns farms and fuzz them from the host side.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--farms", type=int, default=4)
    ap.add_argument("--workers-per-farm", type=int, default=4)
    ap.add_argument("--root", type=Path, default=Path("/var/tmp/cm_veth_farms"))
    ap.add_argument("--out-root", type=Path, default=None)
    ap.add_argument("--iterations", type=int, default=10_000_000)
    ap.add_argument("--ring-size", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=900,
                    help="per-farm fuzz timeout in seconds")
    ap.add_argument("--wall-clock", type=int, default=900,
                    help="overall launcher budget in seconds")
    ap.add_argument("--seed-base-origin", type=lambda s: int(s, 0), default=0xD0000000)
    ap.add_argument("--seed-base-stride", type=lambda s: int(s, 0), default=0x01000000)
    ap.add_argument("--modes", default=",".join(DEFAULT_MODES))
    ap.add_argument("--port", type=int, default=22350)
    ap.add_argument("--codemeter-bin", type=Path, default=Path("/usr/sbin/CodeMeterLin"))
    ap.add_argument("--init-script", type=Path, default=DEFAULT_INIT_SCRIPT)
    ap.add_argument("--supervisor", type=Path, default=DEFAULT_SUPERVISOR,
                    help="samc_light_supervisor.py to import worker/mutation helpers from")
    ap.add_argument("--prefixed-hello-repro", type=Path, default=DEFAULT_PREFIXED_HELLO_REPRO,
                    help="standalone ECDH prefixed-HELLO reproducer used by --modes prefixed_hello")
    ap.add_argument("--ecdh-prefix-supervisor", type=Path, default=DEFAULT_ECDH_PREFIX_SUPERVISOR,
                    help="ECDH prefix fuzzer used by ecdh_prefix_* modes")
    ap.add_argument("--ax-fuzz", type=Path, default=Path("/home/avj/clones/ax_fuzz"))
    ap.add_argument("--ready-timeout", type=float, default=60.0)
    ap.add_argument("--poll-interval", type=float, default=0.25)
    ap.add_argument("--listener-check-interval", type=float, default=1.0)
    ap.add_argument("--worker-join-timeout", type=float, default=8.0)
    ap.add_argument("--progress-interval", type=float, default=30.0)
    ap.add_argument("--netns-prefix", default="cmveth")
    ap.add_argument("--netns-cidr", default="10.210.0.0/16")
    ap.add_argument("--netns-offset", type=int, default=0,
                    help="offset added before allocating each /30 from --netns-cidr")
    ap.add_argument("--replace-existing", action="store_true",
                    help="delete matching pre-existing netns/veth names before setup")
    ap.add_argument("--no-nat", action="store_true",
                    help="skip nft masquerade setup; host-to-netns fuzzing still works")
    ap.add_argument("--nat-out-iface", default="auto")
    ap.add_argument("--nft-table", default=None)
    ap.add_argument("--sweep-body-len", type=int, default=712)
    ap.add_argument("--sweep-body-seed", type=lambda s: int(s, 0), default=0xB0D1E5)
    ap.add_argument("--sweep-opcodes", default="0x00-0xff")
    ap.add_argument("--sweep-skip-opcodes", default="")
    ap.add_argument("--sweep-prefix-zero-bytes", type=int, default=0)
    ap.add_argument("--sweep-patch-sid", action="store_true")
    ap.add_argument("--sweep-body-lengths", default="")
    ap.add_argument("--canary-wait", type=float, default=10.0,
                    help="seconds to watch target after --modes prefixed_hello sends the repro")
    ap.add_argument("--canary-connect-timeout", type=float, default=2.0)
    ap.add_argument("--canary-socket-timeout", type=float, default=2.0)
    ap.add_argument("--canary-process-timeout", type=float, default=15.0)
    ap.add_argument("--ecdh-prefix-opcodes", default="0x00-0xff")
    ap.add_argument("--ecdh-prefix-skip-opcodes", default="")
    ap.add_argument("--ecdh-prefix-lengths", default="1-32")
    ap.add_argument("--ecdh-prefix-known", default="5e355ed6f2")
    ap.add_argument("--ecdh-prefix-include-known-every", type=int, default=0,
                    help="0 disables known-prefix canaries inside ecdh_prefix_* search")
    ap.add_argument("--ecdh-prefix-connect-timeout", type=float, default=2.0)
    ap.add_argument("--ecdh-prefix-socket-timeout", type=float, default=1.5)
    ap.add_argument("--ds-supervisor", type=Path, default=DEFAULT_DS_SUPERVISOR,
                    help="DS supervisor used by ds_* modes")
    ap.add_argument("--ds-helper-dir", type=Path, default=DEFAULT_DS_HELPER_DIR,
                    help="directory containing cm_direct_client_v7.py and "
                         "200_sessions/cmd_0511_template.bin (for ds_* modes)")
    ap.add_argument("--ds-connect-timeout", type=float, default=3.0)
    ap.add_argument("--ds-socket-timeout", type=float, default=3.0,
                    help="per-socket timeout for DS supervisor; ds_cmd00f1_69 "
                         "has ~12 round trips so needs more headroom than ecdh_prefix")
    ap.add_argument("--max-runs-per-farm", type=int, default=0,
                    help="0 = unlimited; cap total runs (across restarts) per farm")
    ap.add_argument("--restart-seed-stride", type=lambda s: int(s, 0), default=0x10000,
                    help="seed advance per restart so each run explores fresh prefix combinations")
    ap.add_argument("--keep-known-cores", action="store_true",
                    help="preserve ALL cores matching a known signature (default: one "
                         "exemplar per farm, rest deleted). New signatures always get "
                         "one exemplar regardless.")
    ap.add_argument("--dry-run", action="store_true")
    return ap


def main() -> int:
    args = build_arg_parser().parse_args()
    if args.farms < 1:
        raise SystemExit("--farms must be >= 1")
    if args.workers_per_farm < 1:
        raise SystemExit("--workers-per-farm must be >= 1")
    if not args.init_script.exists():
        raise SystemExit(f"init script not found: {args.init_script}")
    if not args.supervisor.exists():
        raise SystemExit(f"supervisor not found: {args.supervisor}")
    if not args.prefixed_hello_repro.exists():
        raise SystemExit(f"prefixed HELLO repro not found: {args.prefixed_hello_repro}")
    if not args.ecdh_prefix_supervisor.exists():
        raise SystemExit(f"ECDH prefix supervisor not found: {args.ecdh_prefix_supervisor}")
    if not args.codemeter_bin.exists() and not args.dry_run:
        raise SystemExit(f"codemeter binary not found: {args.codemeter_bin}")

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = args.out_root or Path(f"/home/avj/clones/ax_fuzz/output/veth_farms/{ts}")
    plan = make_plan(args, out_root)
    if any(is_ds_mode(p["mode"]) for p in plan):
        if not args.ds_supervisor.exists():
            raise SystemExit(f"DS supervisor not found: {args.ds_supervisor}")
        for p in (
            args.ds_helper_dir / "cm_direct_client_v7.py",
            args.ds_helper_dir / "200_sessions" / "cmd_0511_template.bin",
        ):
            if not p.exists():
                raise SystemExit(f"missing DS helper file: {p}")
    launcher_config = {
        "timestamp": ts,
        "farms": args.farms,
        "workers_per_farm": args.workers_per_farm,
        "root": str(args.root),
        "out_root": str(out_root),
        "netns_cidr": args.netns_cidr,
        "nat_enabled": not args.no_nat,
        "modes": [p["mode"] for p in plan],
        "plan": [
            {
                **p,
                "farm_root": str(p["farm_root"]),
                "out_dir": str(p["out_dir"]),
                "out_root": str(p["out_root"]),
                "core_dir": str(p["core_dir"]),
            }
            for p in plan
        ],
    }

    print(f"out_root={out_root}")
    print(f"farm_root_base={args.root}")
    print(
        f"farms={args.farms} workers_per_farm={args.workers_per_farm} "
        f"netns_cidr={args.netns_cidr} nat={'off' if args.no_nat else 'on'}"
    )
    for p in plan:
        print(
            f"  farm_{p['farm_idx']:02d}: ns={p['netns']} "
            f"{p['host_ip']} -> {p['target_ip']} mode={p['mode']} "
            f"seed=0x{p['seed_base']:08X}"
        )

    if args.dry_run:
        return 0

    require_root()
    out_root.mkdir(parents=True, exist_ok=True)
    json_write(out_root / "launcher_config.json", launcher_config)
    light = load_light_supervisor(args.supervisor)

    nft_table = args.nft_table or f"cm_samc_veth_{os.getpid()}"
    nat_configured = False
    if not args.no_nat:
        out_iface = default_route_iface() if args.nat_out_iface == "auto" else args.nat_out_iface
        sh([tool("sysctl"), "-w", "net.ipv4.ip_forward=1"])
        try:
            setup_nft_nat(nft_table, args.netns_cidr, out_iface)
        except Exception:
            cleanup_nft_nat(nft_table)
            raise
        nat_configured = True
        print(f"[nat] table={nft_table} source={args.netns_cidr} out={out_iface}")

    try:
        for farm in plan:
            print(f"[setup] farm_{farm['farm_idx']:02d} root={farm['farm_root']} ns={farm['netns']}")
            build_farm_root(farm["farm_root"])
            setup_netns(farm, replace_existing=args.replace_existing)
            spawn_target(farm, args)

        for farm in plan:
            ok = wait_for_ready(farm, args.ready_timeout)
            if not ok:
                raise RuntimeError(
                    f"farm_{farm['farm_idx']:02d} did not become ready; see {farm['ns_log']}"
                )
            if not netns_listener_ready(farm["netns"], args.port):
                raise RuntimeError(f"farm_{farm['farm_idx']:02d} listener not visible inside netns")
            if not tcp_reachable(farm["target_ip"], args.port):
                raise RuntimeError(
                    f"farm_{farm['farm_idx']:02d} target {farm['target_ip']}:{args.port} not reachable from host"
                )
            print(f"[ready] farm_{farm['farm_idx']:02d} target={farm['target_ip']}:{args.port}")
            if farm["mode"] == "prefixed_hello":
                print(f"[canary] farm_{farm['farm_idx']:02d} sending ECDH prefixed HELLO")
                run_prefixed_hello_canary(farm, args)
                summary = json.loads((farm["out_dir"] / "summary.json").read_text())
                reason = summary["result"]["reason"]
                print(
                    f"[canary] farm_{farm['farm_idx']:02d} reason={reason} "
                    f"core_changed={summary['result']['core_changed']} "
                    f"listener_down={summary['result']['listener_down']} "
                    f"target_rc={summary['result']['target_rc']}"
                )
                farm["done"] = True
                farm["stop_reason"] = reason
            elif is_ecdh_prefix_mode(farm["mode"]):
                print(
                    f"[prefix] farm_{farm['farm_idx']:02d} "
                    f"mode={farm['mode']} target={farm['target_ip']}:{args.port}"
                )
                start_ecdh_prefix_supervisor(farm, args)
            elif is_ds_mode(farm["mode"]):
                print(
                    f"[ds] farm_{farm['farm_idx']:02d} "
                    f"mode={farm['mode']} target={farm['target_ip']}:{args.port}"
                )
                start_ds_supervisor(farm, args)
            else:
                start_farm_workers(farm, light, args)

        start = time.monotonic()
        deadline = start + args.wall_clock
        last_progress = 0.0
        print(f"[run] {len(plan)} veth farms running; wall-clock={args.wall_clock}s")

        while True:
            now = time.monotonic()
            alive = [f for f in plan if not f["done"]]
            if not alive:
                break
            if now >= deadline:
                print("[main] wall-clock deadline reached")
                for farm in alive:
                    farm["stop_reason"] = "wall_clock"
                    farm["done"] = True
                break

            for farm in alive:
                elapsed = now - farm["start_mono"]
                target_rc = farm["target_proc"].poll()
                cur_core = newest_core_in(farm["core_dir"])
                prefix_proc = farm.get("prefix_proc")
                prefix_rc = None if prefix_proc is None else prefix_proc.poll()
                workers_exited = (
                    prefix_rc is not None if prefix_proc is not None
                    else all(not p.is_alive() for p in farm["worker_procs"])
                )
                listener_down = False
                last_listener = farm.get("last_listener_check", 0.0)
                if now - last_listener >= args.listener_check_interval:
                    listener_down = not netns_listener_ready(farm["netns"], args.port)
                    farm["last_listener_check"] = now
                    farm["listener_down"] = listener_down
                else:
                    listener_down = bool(farm.get("listener_down", False))
                core_changed = (
                    cur_core is not None and
                    (farm["baseline_core"] is None or
                     cur_core["path"] != farm["baseline_core"]["path"] or
                     cur_core["mtime_ns"] != farm["baseline_core"]["mtime_ns"]) and
                    cur_core["mtime_ns"] >= int(farm["start_wall"] * 1_000_000_000)
                )
                timed_out = elapsed >= args.timeout
                if target_rc is not None or core_changed or listener_down or workers_exited or timed_out:
                    if target_rc is not None or core_changed or listener_down or prefix_rc == 2:
                        reason = "crash_or_restart"
                    elif timed_out:
                        reason = "timeout"
                    elif prefix_proc is not None:
                        reason = "supervisor_exited"
                    else:
                        reason = "workers_exited"
                    result = {
                        "reason": reason,
                        "elapsed": elapsed,
                        "target_rc": target_rc,
                        "core": cur_core,
                        "baseline_core": farm["baseline_core"],
                        "core_changed": core_changed,
                        "listener_down": listener_down,
                        "workers_exited": workers_exited,
                        "supervisor_rc": prefix_rc,
                        "timed_out": timed_out,
                    }
                    print(
                        f"[exit] farm_{farm['farm_idx']:02d} run_{farm['run_idx']} "
                        f"reason={reason} "
                        f"attempts={sum(c.value for c in farm.get('counters', []))} "
                        f"core_changed={core_changed} listener_down={listener_down} "
                        f"target_rc={target_rc} prefix_rc={prefix_rc}"
                    )

                    # --- stop prefix supervisor or light-supervisor workers ---
                    if prefix_proc is not None:
                        # Give the prefix supervisor time to detect the crash,
                        # finish its own worker joins, and write summary.json.
                        grace_deadline = time.monotonic() + args.worker_join_timeout
                        while time.monotonic() < grace_deadline:
                            if prefix_proc.poll() is not None:
                                break
                            if (farm["out_dir"] / "summary.json").exists():
                                break
                            time.sleep(0.25)
                        stop_process_group(prefix_proc)
                        if not (farm["out_dir"] / "summary.json").exists():
                            json_write(farm["out_dir"] / "summary.json", {
                                "result": result,
                                "attempts": None,
                                "target_proc_pid": farm["target_proc"].pid,
                                "target_proc_rc": farm["target_proc"].poll(),
                                "baseline_core": farm.get("baseline_core"),
                                "end_core": newest_core_in(farm["core_dir"]),
                                "netns": farm["netns"],
                                "network": farm["network"],
                                "host_ip": farm["host_ip"],
                                "target_ip": farm["target_ip"],
                                "supervisor_log": str(farm.get("prefix_log")),
                            })
                        try:
                            farm["prefix_log_fh"].close()
                        except Exception:
                            pass
                    else:
                        stop_farm_workers(farm, join_timeout=args.worker_join_timeout)
                        write_farm_summary(farm, light, result)

                    history_entry: dict[str, Any] = {
                        "run_idx": farm["run_idx"],
                        "reason": reason,
                        "elapsed": elapsed,
                        "seed_base": f"0x{farm['seed_base']:08X}",
                        "core_changed": core_changed,
                        "target_rc": target_rc,
                        "supervisor_rc": prefix_rc,
                        "out_dir": str(farm["out_dir"]),
                    }
                    if core_changed and cur_core is not None:
                        core_meta = _process_run_core(farm, cur_core, args)
                        history_entry["core"] = core_meta
                        cls = core_meta.get("classification", "")
                        print(
                            f"[core] farm_{farm['farm_idx']:02d} "
                            f"classification={cls} "
                            f"kept={not core_meta.get('core_deleted', False)}"
                        )
                    _append_farm_history(farm, history_entry)

                    # --- restart or stop? ---
                    remaining = deadline - time.monotonic()
                    max_runs = args.max_runs_per_farm
                    cap_reached = max_runs > 0 and (farm["run_idx"] + 1) >= max_runs
                    # prefixed_hello is a one-shot canary, not a search mode.
                    restartable = farm["mode"] != "prefixed_hello"

                    if not restartable or cap_reached or remaining <= 10:
                        farm["done"] = True
                        farm["done_reason"] = (
                            "max_runs_reached" if cap_reached
                            else "wall_clock_near" if remaining <= 10
                            else reason
                        )
                    else:
                        # Restart: the netns and veth pair persist across restarts;
                        # only the target process (daemon) and the supervisor need
                        # to be replaced.
                        stop_process_group(farm.get("target_proc"))
                        try:
                            farm["target_log_fh"].close()
                        except Exception:
                            pass

                        farm["run_idx"] += 1
                        farm["seed_base"] = (
                            farm["original_seed_base"]
                            + farm["run_idx"] * args.restart_seed_stride
                        )
                        farm["out_dir"] = _out_dir_for_run(
                            farm["out_root"], farm["farm_idx"], farm["run_idx"]
                        )
                        # Reset per-run listener state so the new run doesn't
                        # immediately re-trigger on the just-crashed listener.
                        farm["listener_down"] = False
                        farm["last_listener_check"] = 0.0
                        # Snapshot cores now so the new run only detects fresh ones.
                        farm["baseline_core"] = newest_core_in(farm["core_dir"])

                        spawn_target(farm, args)
                        ok = wait_for_ready(farm, args.ready_timeout)
                        if not ok:
                            print(
                                f"[ready] farm_{farm['farm_idx']:02d} "
                                f"run_{farm['run_idx']} FAILED after restart"
                            )
                            farm["done"] = True
                            farm["done_reason"] = "restart_readiness_failed"
                        else:
                            farm["start_wall"] = time.time()
                            farm["start_mono"] = time.monotonic()
                            if is_ecdh_prefix_mode(farm["mode"]):
                                start_ecdh_prefix_supervisor(farm, args)
                            elif is_ds_mode(farm["mode"]):
                                start_ds_supervisor(farm, args)
                            else:
                                start_farm_workers(farm, light, args)
                            print(
                                f"[restart] farm_{farm['farm_idx']:02d} "
                                f"run_{farm['run_idx']} "
                                f"seed=0x{farm['seed_base']:08X} "
                                f"target={farm['target_ip']}:{args.port}"
                            )

            if now - last_progress >= args.progress_interval:
                desc = []
                for farm in [f for f in plan if not f["done"]]:
                    if "prefix_proc" in farm:
                        attempts = None
                        summary_path = farm["out_dir"] / "summary.json"
                        if summary_path.exists():
                            try:
                                attempts = json.loads(summary_path.read_text()).get("attempts")
                            except Exception:
                                attempts = None
                        desc.append(f"{farm['farm_idx']:02d}:prefix:{attempts}")
                        continue
                    desc.append(
                        f"{farm['farm_idx']:02d}:{sum(c.value for c in farm['counters'])}"
                    )
                print(f"[tick] t+{int(now - start)}s alive_attempts=[{','.join(desc)}]")
                last_progress = now
            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("\n[int] keyboard interrupt; stopping farms")
        for farm in plan:
            if not farm.get("done") and "prefix_proc" in farm:
                stop_process_group(farm["prefix_proc"])
            elif not farm.get("done") and "worker_procs" in farm:
                stop_farm_workers(farm, join_timeout=args.worker_join_timeout)
                write_farm_summary(farm, light, {"reason": "interrupted"})
    finally:
        for farm in plan:
            if "prefix_proc" in farm and not farm.get("done"):
                stop_process_group(farm["prefix_proc"])
            elif "worker_procs" in farm and not farm.get("done"):
                stop_farm_workers(farm, join_timeout=args.worker_join_timeout)
                write_farm_summary(farm, light, {"reason": farm.get("done_reason", "launcher_shutdown")})
            stop_process_group(farm.get("target_proc"))
            try:
                if farm.get("target_log_fh") is not None:
                    farm["target_log_fh"].close()
            except Exception:
                pass
            try:
                if farm.get("prefix_log_fh") is not None:
                    farm["prefix_log_fh"].close()
            except Exception:
                pass
            cleanup_netns(farm)
        if nat_configured:
            cleanup_nft_nat(nft_table)

    final = {
        "out_root": str(out_root),
        "farms": [
            {
                "farm_idx": f["farm_idx"],
                "netns": f["netns"],
                "target_ip": f["target_ip"],
                "mode": f["mode"],
                "done_reason": f.get("done_reason"),
                "total_runs": f["run_idx"] + 1,
                "history_count": len(f.get("history", [])),
                "final_out_dir": str(f["out_dir"]),
            }
            for f in plan
        ],
    }
    json_write(out_root / "final_report.json", final)
    print(f"[done] out_root={out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
