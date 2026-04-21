# Fuzzer used to find this bug

Stateful samc-protocol fuzzer in Python. Talks to a **live** CodeMeterLin on
`127.0.0.1:22350`; does not instrument or wrap the daemon in any way.

## Files

| file | purpose |
|---|---|
| `repro_prefixed_hello.py` | deterministic one-packet reproducer for the isolated crash |
| `repro_prefixed_hello_standalone.py` | same HELLO reproducer as a single file; no project-local imports or data files |
| `repro_ack_0x5e.py` | ACK-side two-frame reproducer candidate: normal HELLO, then crafted opcode-`0x5e` ACK |
| `samc_light_supervisor.py` | high-throughput 16-worker attribution harness with per-worker ring dumps |
| `samc_fuzz.py` | main fuzzer loop; stateful session replay with per-iteration mutation |
| `samc_session_data.py` | canonical cleartext plaintexts captured from a real testbench session |
| `samc_replay.py` | single-input replay harness (for crash triage) |
| `run_samc_fuzz_parallel.sh` | launches N concurrent workers (default 16) |
| `fuzz_farm_launcher.py` | host-side driver for multi-farm namespaced fuzzing with crash-signature bucketing and auto-restart |
| `fuzz_farm_namespace_init.sh` | PID-1 init script each farm's namespace runs; mounts, starts daemon, execs supervisor |

For the multi-daemon scale-out design and what the first 1-hour 8×10 run
revealed, see [`../MULTI_INSTANCE_FUZZING.md`](../MULTI_INSTANCE_FUZZING.md).
The short version: Linux namespaces can run multiple isolated `CodeMeterLin`
instances on the same host, each farm needs private `/tmp`, `/dev/shm`,
config/state directories, IPC, and network namespaces, and the supervisor
needs `--no-service-check` and a restricted `--core-dir` to work correctly
inside a farm.

## Prerequisites

- `python3` ≥ 3.10 (uses `list[bytes]` type hints)
- `python3-cryptography` (for AES-128-CBC)
- A running CodeMeterLin on `127.0.0.1:22350` (just `systemctl start codemeter`)
- Run as the `daemon` user OR any user with `NOPASSWD` sudo for `systemctl
  restart codemeter` + `rm /var/lock/cm_lock` (auto-restart on crash).

## Run

Deterministic one-packet crash reproducer:

```bash
python3 repro_prefixed_hello.py
```

This intentionally crashes the daemon by sending a single valid encrypted
SAMC HELLO whose cleartext is prefixed with `5e355ed6f2`.

Standalone version with no project-local imports:

```bash
python3 repro_prefixed_hello_standalone.py
```

Use `--dry-run` to construct and print the packet summary without sending it.

ACK-side candidate reproducer:

```bash
python3 repro_ack_0x5e.py
```

This sends a normal fresh-token HELLO, extracts the returned SID, patches it
into the canonical ACK, then prepends one of the captured opcode-`0x5e` ACK
prefixes before sending the ACK. Use `--prefix 5e` or another hex prefix to
test minimization candidates.

Single instance:

```bash
python3 samc_fuzz.py --iterations 1000 --seed 42 --out-dir /tmp/fuzz_out
```

16-worker parallel, writing to `$REPO/output/samc_fuzz_par/`:

```bash
WORKERS=16 ITERATIONS=10000000 ./run_samc_fuzz_parallel.sh
```

16-worker attribution run, preserving each worker's last real sent sessions
when the daemon crashes:

```bash
python3 samc_light_supervisor.py \
  --out-dir /tmp/samc_light_$(date +%Y%m%d_%H%M%S) \
  --workers 16 \
  --mode mixed \
  --iterations 10000000 \
  --ring-size 100 \
  --seed-base 0xC0D30000 \
  --timeout 900
```

## What it does per iteration

1. Connect to `127.0.0.1:22350`.
2. Encrypt + send the canonical HELLO plaintext (replacing the 4-byte
   client token at offset 28 with a fresh random value so the daemon
   doesn't reject it as a replay).
3. Receive daemon's 8-byte cookie response, decrypt, extract the last
   4 bytes as the session ID (SID).
4. Encrypt + send the canonical `0x0b` ACK plaintext with the SID patched
   in at offset 4.
5. Encrypt + send the canonical 712-byte `0x64` request plaintext.
6. In whichever of the above frames is the *fuzz target* for this
   iteration (rotates across HELLO/ACK/`0x64` by default), apply a random
   mutation (bit-flip, byte-flip, random insert/delete, length extend,
   truncate, dictionary splice, boundary-value substitution) before
   encrypting.
7. Close the connection.
8. Every 10 iterations, check whether the daemon PID changed or a new
   coredump appeared; if so, save the last-sent plaintext as a crash
   artefact under `<out>/crashes/`, and restart the daemon via
   `sudo systemctl restart codemeter` (serialized with `flock`).

`samc_light_supervisor.py` uses the same session replay and mutation semantics
but centralizes crash detection in a supervisor. It detects raw cores in
`/var/tmp/cm_cores`, uses `pgrep -x CodeMeterLin`, and dumps worker rings only
after stop/crash so attribution is not lost to post-crash connection-refused
attempts.

## Lightweight Orchestrator Design

`samc_light_supervisor.py` is the orchestrator used to reduce the crash. It is
not a replacement protocol fuzzer; it is a thin wrapper around the original
fuzzing behavior with better attribution.

Changes from `run_samc_fuzz_parallel.sh` + `samc_fuzz.py`:

| area | old behavior | orchestrator behavior |
|---|---|---|
| crash detection | each worker checks every 10 iterations | one supervisor polls PID/core/listener/service state |
| PID matching | `pgrep -f` can match unrelated command lines | exact `pgrep -x CodeMeterLin` |
| core detection | systemd-coredump path only | `/var/tmp/cm_cores` and systemd-coredump |
| restart | workers race to restart after detection | supervisor stops workers; restart is left to the operator |
| saved inputs | only the current worker's last mutation, often a bystander | each worker dumps an in-memory ring of recent sent sessions |
| hot-path I/O | low, but attribution poor | still low; writes plaintexts only after stop/crash |

The ring-buffer detail matters. The first version of the orchestrator
successfully reproduced the crash, but while the raw core was being written the
workers kept looping and their last-100 rings became only `Connection refused`
attempts. The current version stores only attempts that sent at least one frame,
so post-crash connection failures cannot evict the useful pre-crash traffic.

Output layout:

```text
<out-dir>/
  run_config.json
  summary.json
  worker_09/
    worker_summary.json
    ring_manifest.jsonl
    ring/
      iter_00004667/
        attempt.json
        frame_0_plaintext.bin
```

`attempt.json` records the worker ID, iteration, target frame, token, mutation
metadata, send timestamps, response status, and paths to the plaintext frames.
The plaintext `.bin` files are the artifacts to replay or inspect with `xxd`.

## Isolated Crash

The reduced trigger is a HELLO mutation:

```text
insert bytes: 5e 35 5e d6 f2
insert pos:   0
frame:        0 (HELLO)
```

The shifted cleartext begins:

```text
5e 35 5e d6 f2 0a 00 00 00 00 00 00 10 00 00 28
```

That causes the parser to cache `0x28000010` at `this + 0x68`; the value later
reaches the `memcpy` length at `CodeMeterLin + 0x8f431d`.

## Crypto used

- Session key derivation: `SHA-1(<little-endian u32 of magic_div_1009(time(NULL))>)`
  → first 16 bytes = AES-128 key, bytes [4:20] = IV.
- AES-128-CBC + CTS (swap last two ciphertext blocks).
- MAC tail: `8 zero bytes || length_u32_le || crc32_u32_le` appended to the
  plaintext before encryption; length fits the aligned 16-byte block size.

All derived from publicly observable behaviour of testbench clients and
the matching daemon decode paths; no private crypto material used.
