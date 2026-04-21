# Multi-Instance Fuzz Farms with Linux Namespaces

## Status

Launcher exists and has run end-to-end (2026-04-21):

- `fuzzer/fuzz_farm_launcher.py` — host-side driver. Builds farm roots,
  spawns one `unshare`-wrapped init per farm, tracks per-farm run lifecycle,
  extracts a gdb signature from each crash core, buckets by first-binary-frame
  offset, restarts known-crash farms with a bumped seed base, stops new-crash
  farms and preserves artifacts.
- `fuzzer/fuzz_farm_namespace_init.sh` — runs as PID 1 inside each namespace.
  Does the mount/bind dance, starts `CodeMeterLin`, waits for the listener,
  execs `samc_light_supervisor.py`.
- First real run: **8 farms × 10 workers × 1 hour wall-clock, 23.2M attempts,
  67 crashes, all classified as `memcpy_8f431d_prefixed_hello`**. See
  [First 1-hour run: findings](#first-1-hour-run-findings) at the end of this
  document for what the run revealed about reachability of the known crash
  from ACK vs. `0x64` frames.

The rest of this document captures the design, the manual proof it was built
from, and the detector fixes that were needed once the supervisor moved
from the host into a namespace.

## Key Finding

`CodeMeterLin` has more than one singleton resource.

The first namespace attempt isolated the config/state directories, `/run/lock`,
IPC, network, and `/dev/shm`, but left `/tmp` shared with the host. That
isolated daemon started, created private `/dev/shm/CME-*` files, then exited
with status 1 before listening.

`strace` showed the reason:

```text
openat(..., "/tmp/cm_lock", O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK, 0666) = -1 EEXIST
flock(...) = -1 EAGAIN
exit_group(1)
```

So `/tmp/cm_lock` is a process-wide singleton lock. A private `/tmp` is
required. Once `/tmp` was mounted as a private tmpfs inside the namespace, the
isolated daemon started and listened normally.

## Minimum Isolation Set

Each farm needs its own:

```text
mount namespace
IPC namespace
network namespace
PID namespace
UTS namespace
private /tmp
private /dev/shm
private /run/lock
private /etc/wibu/CodeMeter
private /var/lib/CodeMeter
private /var/log/CodeMeter
private /var/tmp/cm_cores
```

The namespace init must also bring up loopback:

```bash
ip link set lo up
```

The daemon can then bind `22350` inside that namespace without conflicting with
other farms, because each farm has its own network namespace.

## Manual Proof Shape

This is the shape that worked. Paths should be made unique per farm.

```bash
ROOT=/var/tmp/codemeter_ns_test2

sudo mkdir -p \
  "$ROOT/etc/wibu/CodeMeter" \
  "$ROOT/var/lib/CodeMeter" \
  "$ROOT/var/log/CodeMeter" \
  "$ROOT/run/lock" \
  "$ROOT/var/tmp/cm_cores" \
  "$ROOT/work"

sudo cp -a /etc/wibu/CodeMeter/. "$ROOT/etc/wibu/CodeMeter/"
sudo cp -a /var/lib/CodeMeter/. "$ROOT/var/lib/CodeMeter/"
sudo cp -a /var/log/CodeMeter/. "$ROOT/var/log/CodeMeter/"
sudo chown daemon:daemon "$ROOT/work" "$ROOT/var/tmp/cm_cores"
```

Then start the isolated daemon:

```bash
sudo unshare --fork --pid --mount-proc --mount --ipc --net --uts bash -lc '
set -euo pipefail
ROOT=/var/tmp/codemeter_ns_test2

hostname cmns2 || true
mount --make-rprivate /
mount --bind "$ROOT/etc/wibu/CodeMeter" /etc/wibu/CodeMeter
mount --bind "$ROOT/var/lib/CodeMeter" /var/lib/CodeMeter
mount --bind "$ROOT/var/log/CodeMeter" /var/log/CodeMeter
mount --bind "$ROOT/run/lock" /run/lock
mount --bind "$ROOT/var/tmp/cm_cores" /var/tmp/cm_cores
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
ip link set lo up

cd "$ROOT/work"
runuser -u daemon -- /usr/sbin/CodeMeterLin -f
'
```

The proof run used a wrapper that backgrounded `CodeMeterLin`, waited for
`ss -tln "( sport = :22350 )"` inside the namespace, and then kept the namespace
alive for inspection.

## Proof Checks

Use the namespace init process as the `nsenter` target. In the proof run the
init PIDs were temporary host PIDs such as `593805` and `594122`.

Check the namespaced daemon and listener:

```bash
sudo nsenter -t "$INIT_PID" -a bash -lc '
hostname
pgrep -a -x CodeMeterLin
ss -tlnp "( sport = :22350 )"
python3 - << "PY"
import socket
s = socket.create_connection(("127.0.0.1", 22350), 2)
print("connected", s.getsockname(), "->", s.getpeername())
s.close()
PY
'
```

Check namespace separation from the host:

```bash
for pid in "$HOST_CODEMETER_PID" "$FARM0_CODEMETER_PID" "$FARM1_CODEMETER_PID"; do
  printf 'pid=%s net=' "$pid"; sudo readlink "/proc/$pid/ns/net"
  printf 'pid=%s ipc=' "$pid"; sudo readlink "/proc/$pid/ns/ipc"
  printf 'pid=%s mnt=' "$pid"; sudo readlink "/proc/$pid/ns/mnt"
done
```

Observed proof-run evidence:

```text
host CodeMeterLin:
  net:[4026531833] ipc:[4026531839] mnt:[4026531832]

cmns2 CodeMeterLin:
  net:[4026532828] ipc:[4026532826] mnt:[4026532824]

cmns3 CodeMeterLin:
  net:[4026532666] ipc:[4026532664] mnt:[4026532662]
```

Inside each successful namespace, `ss` showed a listener like:

```text
LISTEN 0 511 0.0.0.0:22350 0.0.0.0:* users:(("CodeMeterLin",pid=38,fd=8))
LISTEN 0 511    [::]:22350    [::]:* users:(("CodeMeterLin",pid=38,fd=9))
```

## 16-Farm Design

The proposed scale-out topology is:

```text
farm_00 namespace:
  CodeMeterLin
  samc_light_supervisor.py --workers 16 --seed-base 0xC0D30000

farm_01 namespace:
  CodeMeterLin
  samc_light_supervisor.py --workers 16 --seed-base 0xC1D30000

...

farm_15 namespace:
  CodeMeterLin
  samc_light_supervisor.py --workers 16 --seed-base 0xCFD30000
```

Important: run `samc_light_supervisor.py` inside the same namespace as its
daemon. Do not run all supervisors from the host namespace. The supervisor's
checks are namespace-sensitive:

```text
127.0.0.1:22350          must mean this farm's daemon
pgrep -x CodeMeterLin    must see this farm's daemon
ss -tln                  must see this farm's network namespace
/var/tmp/cm_cores        must be this farm's private core directory
```

A host-side launcher should therefore start one namespace per farm and launch
both the daemon and the supervisor inside it.

## Seed and Mode Sharding

If all farms run the same mixed mode, they may rediscover the known
prefixed-HELLO crash. For finding more bugs, shard the work:

```text
some farms: --mode hello
some farms: --mode ack
some farms: --mode big
some farms: --mode rotate
```

Use non-overlapping seed ranges:

```text
farm_00 seed base: 0xC0D30000
farm_01 seed base: 0xC1D30000
farm_02 seed base: 0xC2D30000
...
farm_15 seed base: 0xCFD30000
```

The launcher should write each farm under a separate output root, for example:

```text
/home/avj/clones/ax_fuzz/output/farms/<timestamp>/farm_00/
/home/avj/clones/ax_fuzz/output/farms/<timestamp>/farm_01/
...
```

## Crash Bucketing

The farm launcher should distinguish known crashes from new crashes.

Known crash signature:

```text
libc memcpy/memmove
CodeMeterLin + 0x8f431d
large copy length derived from malformed HELLO parser state
```

For a known crash, preserve the farm output and optionally restart that farm
with a new seed base. For a new crash, preserve the namespace root, core,
supervisor output, and recent worker rings, then stop or alert loudly.

The current `samc_light_supervisor.py` stops on the first crash and records the
worker rings. A farm launcher can layer restart and bucketing around it.

## Resource Cautions

The full target topology is heavy:

```text
16 farms * 1 CodeMeterLin each = 16 daemons
16 farms * 16 workers each     = 256 fuzz workers
```

Before a full run, ramp up in stages:

```text
16 farms * 1 worker
16 farms * 4 workers
16 farms * 8 workers
16 farms * 16 workers
```

Watch CPU saturation, memory use, raw core write pressure, and whether workers
start spending most of their time in connection setup rather than useful
mutation throughput.

## Core Capture

Each namespace should set full-core behavior before starting the daemon:

```bash
ulimit -c unlimited
echo 0xff > /proc/self/coredump_filter
```

The farm root should bind its private core directory over `/var/tmp/cm_cores`:

```text
$FARM_ROOT/var/tmp/cm_cores -> /var/tmp/cm_cores
```

That keeps cores separated by farm and avoids overwriting or confusing the host
daemon's core artifacts.

## Cleanup

The launcher must track the host PIDs of each namespace init process. Cleanup
should kill the namespace init process, wait for its children to exit, then
remove the farm root only if the farm did not produce an interesting crash.

Manual cleanup pattern:

```bash
sudo kill "$INIT_PID"
sleep 1
sudo kill -KILL "$INIT_PID" 2>/dev/null || true
```

Then confirm that only the host daemon remains:

```bash
pgrep -a -x CodeMeterLin
systemctl is-active codemeter
sudo ss -tlnp 'sport = :22350'
```

## Implementation status

The host-side launcher described above is implemented in
`fuzzer/fuzz_farm_launcher.py` and `fuzzer/fuzz_farm_namespace_init.sh`.

Done:

1. Creates `N` farm roots.
2. Copies `/etc/wibu/CodeMeter`, `/var/lib/CodeMeter`, `/var/log/CodeMeter`
   into each root (only on first use; subsequent runs reuse the state).
3. Starts one namespace per farm with the isolation set above.
4. Starts `CodeMeterLin` inside each namespace.
5. Waits for each farm's listener to become ready.
6. Starts `samc_light_supervisor.py` inside each namespace with unique
   `--out-dir`, `--seed-base`, `--mode`, `--workers`.
7. Watches all supervisors under a single wall-clock budget (`--wall-clock`).
8. Buckets crashes by signature via `gdb -batch` (top frames rendered as
   `CodeMeterLin+0xNNN` offsets; first binary-local frame is the bucket key).
9. Restarts known-crash farms with a bumped seed base
   (`original + run_idx * 0x10000`) and writes each run to `run_N/` under the
   farm's output directory.
10. Stops new-signature farms on first hit so the core + ring dumps are
    preserved for triage; emits a `[NEW ]` alert line.

Deferred:

- Auto-copy of new-signature artifacts to a dedicated quarantine directory
  (currently the artifacts are simply left in place under
  `farm_NN/run_N/`).
- Restart-on-timeout seed policies other than a single linear advance.
- Structural / opcode-aware mutators (see findings below for why this
  matters).

## Detector fixes for namespaced operation

The first launcher run exposed two bugs in `samc_light_supervisor.py` that
only surface once the supervisor is moved from the host into a fuzz-farm
namespace. Both are fixed; the supervisor now accepts two flags that the
launcher passes by default:

1. `--no-service-check`. The supervisor originally used
   `systemctl is-active codemeter` as one of the union of crash-detection
   signals. Inside a fresh PID namespace, `systemctl` returns non-zero
   (D-Bus/systemd is not where it expects), the probe throws
   `CalledProcessError`, and `service_state()` returns `"unknown:..."`.
   That is `!= "active"`, so `service_inactive` fired on the first poll of
   every farm and every farm was reported as crashed 20 ms after startup.
   With `--no-service-check`, the supervisor skips the probe entirely —
   sensible because inside a farm the daemon is not systemd-managed anyway.
   PID / listener / core checks are unaffected.

2. `--core-dir PATH` (repeatable). The supervisor originally watched both
   `/var/tmp/cm_cores` and `/var/lib/systemd/coredump`. Inside a farm,
   `/var/tmp/cm_cores` is a private bind mount (per-farm cores only), but
   `/var/lib/systemd/coredump` is still the host path — shared across all
   farms. Without restricting the watched set, a crash in farm A would also
   show up as a new core in farm B's supervisor, masquerading as a
   simultaneous crash. The launcher passes `--core-dir /var/tmp/cm_cores`
   so each supervisor only sees its own farm's cores.

## First 1-hour run: findings

8 farms × 10 workers × 1 h wall-clock, 10 min per-run supervisor timeout,
seed bases `0xC0000000 + i * 0x01000000` with `+0x10000` per restart, modes
cycled `mixed,hello,ack,big,rotate,mixed,mixed,hello`.

Outcome:

| | |
|---|---|
| Total supervisor runs | 91 (67 crashes, 24 timeouts) |
| Total fuzz attempts | 23.2 million across 80 workers |
| Unique crash signatures | **1** — `memcpy_8f431d_prefixed_hello` |
| New signatures | 0 |

Per mode:

| mode | crashes | timeouts | notes |
|------|--------:|---------:|-------|
| ack    | **22** | 1 | single ack-only farm — most efficient trigger |
| mixed  | 35 | 5 | three mixed farms, consistent |
| hello  | 8  | 8 | two hello-only farms — random mutation hits the specific 5-byte trigger only ~half the time |
| rotate | 2  | 5 | iteration-rotated target frame; bug reached only when rotation lands on a crashable frame |
| big    | **0** | **5** | **`0x64` request mutation never reached `+0x8f431d` in ~2.5 M attempts** |

What this tells us beyond the reduced prefixed-HELLO repro:

1. **The `+0x8f431d` memcpy is reachable from the ACK decoder as well as
   the HELLO decoder.** The ack-only farm crashed 22 times in 1 hour, all on
   the same stack. `ack` mode sends the canonical HELLO *unmodified* —
   only the ACK frame is mutated — so the trigger must live in the ACK
   parse path itself, not in cross-frame state inherited from HELLO.
   This is a dynamic complement to the opcode-`0x5e`/helper-`+0x8f3d60`
   story in `BUG_CLASS_AUDIT.md`: both HELLO and ACK byte-level
   mutations evidently produce inputs that route through the same
   vulnerable dispatch helper.

2. **The `0x64` request frame does not reach `+0x8f431d` under this
   mutator.** 2.5 M byte-level mutations of the 712-byte `0x64` plaintext
   produced zero crashes. Either the `0x64` parser genuinely does not
   reach the `+0x8f3d60` helper, or the byte-level mutator is too shallow
   on a large structured frame to produce the required shape. Structural
   / opcode-aware mutation on `0x64` is the next meaningful coverage
   experiment.

3. **The fuzzer is saturated on one bug.** With no coverage feedback and
   no worker-side filter for the known crash, every run dead-ends on
   `+0x8f431d`. To observe a second signature we need to either un-shadow
   the known bug (worker-side reject inputs with the known trigger shape,
   or skip the known-crash dispatch somehow) or run deliberately narrowed
   experiments such as `big`-only with a structural mutator.

