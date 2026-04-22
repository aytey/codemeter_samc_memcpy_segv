# Fuzzers and reproducers

Stateful SAMC and daemon-to-server fuzzing tools plus deterministic reproducers.
Most tools talk to a **live** `CodeMeterLin`; they do not instrument or wrap
the daemon in any way. See `../README.md` and `../RESEARCH_LOG.md` for the
current crash story and campaign chronology.

## Files

| file | purpose |
|---|---|
| `repro_prefixed_hello.py` | deterministic one-packet reproducer for the isolated crash |
| `repro_prefixed_hello_standalone.py` | same HELLO reproducer as a single file; no project-local imports or data files |
| `repro_ack_0x5e.py` | ACK-side two-frame reproducer: normal HELLO, live SID extraction, then crafted opcode-`0x5e` ACK |
| `repro_prefixed_ack_standalone.py` | standalone ACK-side reproducer: normal HELLO, live SID extraction, then zero-tail prefixed ACK over PSK/ECDH |
| `samc_light_supervisor.py` | high-throughput 16-worker attribution harness with per-worker ring dumps |
| `samc_fuzz.py` | main fuzzer loop; stateful session replay with per-iteration mutation |
| `samc_session_data.py` | canonical cleartext plaintexts captured from a real testbench session |
| `samc_replay.py` | single-input replay harness (for crash triage) |
| `run_samc_fuzz_parallel.sh` | launches N concurrent workers (default 16) |
| `fuzz_farm_launcher.py` | host-side driver for multi-farm namespaced fuzzing with crash-signature bucketing and auto-restart |
| `fuzz_farm_namespace_init.sh` | PID-1 init script each farm's namespace runs; mounts, starts daemon, execs supervisor |
| `remote_cm_fuzz_launcher.py` | remote daemon-to-server protocol fuzzer with SSH-based target crash monitoring |
| `samc_veth_farm_launcher.py` | local multi-daemon farm where fuzz traffic reaches each daemon over a veth address, not loopback |
| `samc_veth_target_init.sh` | target-only namespace init used by `samc_veth_farm_launcher.py` |
| `samc_ecdh_prefix_supervisor.py` | ECDH-channel prefix/dispatcher fuzzer for HELLO and ACK parser-shift bugs |
| `samc_ds_supervisor.py` | daemon→server protocol fuzzer (0x0021/0x0511/0x0031/0x00f1 sub=0x5a,0x69) for veth farm targets |
| `run_confirm_candidate.sh` | single-worker confirmation run for one (mode, opcode, prefix_len) candidate |

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
SAMC HELLO whose cleartext is prefixed with `5e00000000`. The older captured
`5e355ed6f2` prefix reaches the same shifted layout and can still be selected
with `--prefix`.

For a non-loopback network-server target, the same reproducer now uses the
ECDH-selected channel by default:

```bash
python3 repro_prefixed_hello.py --host vistrrdslin0004.vi.vector.int
```

This still uses the outer `samc` envelope, but sends `0xa2 0x05` ECDH init
first and then sends the prefixed HELLO as an encrypted `0xa1` payload. The
local PID/core crash oracle is skipped for non-loopback targets.

Standalone version with no project-local imports:

```bash
python3 repro_prefixed_hello_standalone.py
```

Use `--dry-run` to construct and print the packet summary without sending it.
Like the import-based version, it automatically uses the ECDH-selected `0xa1`
channel for non-loopback targets.

ACK-side reproducer:

```bash
python3 repro_ack_0x5e.py
```

This sends a normal fresh-token HELLO, extracts the returned SID, patches it
into the canonical ACK, then prepends a zero-tail opcode-`0x5e` ACK prefix
before sending the ACK. Use `--sample-prefix N` for the older captured
random-tail prefixes, or `--prefix 5e` / another hex prefix to test
minimization candidates. Like the HELLO repro, `--channel auto` uses PSK for
loopback targets and ECDH for non-loopback targets.

Standalone ACK-side version with no project-local imports:

```bash
python3 repro_prefixed_ack_standalone.py
```

This builds the canonical HELLO and ACK internally. It sends HELLO first,
decrypts the daemon response to extract the live SID, then sends
`5e0000000000000000000000000000 || 0b000000 || SID` as the second
application frame. Like the standalone HELLO repro, `--channel auto` uses PSK
for loopback targets and ECDH for non-loopback targets.

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

Remote CodeMeter server protocol fuzzing from one host against another:

```bash
python3 remote_cm_fuzz_launcher.py \
  --target-host vistrrdslin0004.vi.vector.int \
  --ssh-host vistrrdslin0004.vi.vector.int \
  --workers 4 \
  --iterations 100000 \
  --mode query0031
```

This exercises the daemon-to-server ECDH protocol, starts each worker with a
valid auth/init exchange, fuzzes encrypted `0x0031` query records by default,
and watches the remote `CodeMeterLin` PID/core state over SSH. Use
`--mode auth0021` for pre-auth 32-byte record fuzzing or `--mode mixed` to
blend both.

Local remote-looking SAMC farm:

```bash
sudo python3 samc_veth_farm_launcher.py \
  --farms 4 \
  --workers-per-farm 4 \
  --modes sweep,ack,hello,big \
  --wall-clock 900 \
  --timeout 900
```

This starts one `CodeMeterLin` per network namespace, with a veth pair per
farm. The fuzz workers run on the host and connect to each target namespace IP
such as `10.210.0.2:22350`, so the daemon sees the SAMC peer as the host-side
veth address instead of `127.0.0.1`. By default the launcher also installs an
nftables masquerade rule for namespace outbound traffic; use `--no-nat` if only
host-to-namespace fuzzing is needed.

To check the veth farm against the known remote/ECDH HELLO trigger:

```bash
sudo python3 samc_veth_farm_launcher.py \
  --farms 1 \
  --workers-per-farm 1 \
  --modes prefixed_hello \
  --wall-clock 60 \
  --timeout 60
```

`prefixed_hello` is a deterministic canary mode. It sends
`repro_prefixed_hello_standalone.py` over the ECDH `0xa1` channel to the
namespace target and records whether the farm-private crash oracle saw the
target die, lose its listener, or write a core.

Purpose-built search for the same bug class:

```bash
sudo python3 samc_veth_farm_launcher.py \
  --farms 4 \
  --workers-per-farm 4 \
  --modes ecdh_prefix_hello,ecdh_prefix_ack \
  --ecdh-prefix-opcodes 0x00-0xff \
  --ecdh-prefix-lengths 1-32 \
  --wall-clock 900 \
  --timeout 900
```

The `ecdh_prefix_*` modes keep the ECDH selector channel, length, CRC, HELLO
token, and ACK session-id patching valid, then fuzz only the parser-visible
prefix before canonical messages. This is designed to find dispatcher/field
shift failures like the `5e00000000 || HELLO` crash without relying on a random
insert to rediscover the exact five bytes. Use
`--ecdh-prefix-include-known-every N` to inject the known prefix periodically as
a regression canary during longer campaigns; leave it at `0` to avoid the known
crash shadowing new signatures.

Daemon-to-server protocol coverage (all five message kinds):

```bash
sudo python3 samc_veth_farm_launcher.py \
  --farms 4 \
  --workers-per-farm 4 \
  --modes ds_mixed \
  --wall-clock 900 \
  --timeout 900
```

The `ds_*` modes speak the full ECDH+daemon→server protocol sequence against
each veth-backed daemon, fuzzing one of five record types per iteration:

| mode | fuzz target | prior setup |
|---|---|---|
| `ds_auth0021` | 32B auth record | ECDH only |
| `ds_init0511` | 1296B init record (template-based) | ECDH + fixed auth |
| `ds_query0031` | 48B query record | ECDH + fixed auth + fixed init |
| `ds_cmd00f1_5a` | 240B sub=0x5a SEED-query | ECDH + auth + init + 3 queries + re-auth |
| `ds_cmd00f1_69` | 240B sub=0x69 SEED-exchange | full 0x5a sequence + re-auth + 2 queries |
| `ds_mixed` | weighted blend of all above | — |

Requires `--ds-helper-dir` pointing to a directory with `cm_direct_client_v7.py`
and `200_sessions/cmd_0511_template.bin` (defaults to
`/home/avj/clones/ax_decrypt/009/research_scripts`).

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

The original reduced trigger was a HELLO mutation:

```text
insert bytes: 5e 35 5e d6 f2
insert pos:   0
frame:        0 (HELLO)
```

That historical prefix is no longer believed to be special. The current
simplified HELLO trigger is:

```text
5e 00 00 00 00 || canonical HELLO
```

The shifted cleartext begins:

```text
5e 00 00 00 00 0a 00 00 00 00 00 00 10 00 00 28
```

That causes the parser to cache `0x28000010` at `this + 0x68`; the value later
reaches the `memcpy` length at `CodeMeterLin + 0x8f431d`.

The same crash is also reachable through ACK after a normal HELLO/SID exchange:

```text
5e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 || 0b 00 00 00 || SID
```

The 6-hour ECDH prefix campaign produced 360 classified crashes and no new
signatures. Its main result was to confirm that both the HELLO and ACK routes
are simpler zero-tail opcode-`0x5e` parser-shift cases, not special properties
of the original random-tail bytes.

## Crypto used

- Session key derivation: `SHA-1(<little-endian u32 of magic_div_1009(time(NULL))>)`
  → first 16 bytes = AES-128 key, bytes [4:20] = IV.
- AES-128-CBC + CTS (swap last two ciphertext blocks).
- MAC tail: `8 zero bytes || length_u32_le || crc32_u32_le` appended to the
  plaintext before encryption; length fits the aligned 16-byte block size.

All derived from publicly observable behaviour of testbench clients and
the matching daemon decode paths; no private crypto material used.
