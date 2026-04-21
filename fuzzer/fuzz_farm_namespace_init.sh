#!/bin/bash
# fuzz_farm_namespace_init.sh
#
# Runs as PID 1 inside an unshare --fork --pid --mount-proc --mount --ipc --net --uts
# child created by fuzz_farm_launcher.py. Sets up the isolation the CodeMeterLin
# daemon needs (private /tmp, /dev/shm, /run/lock, config/state dirs, core dir),
# starts the daemon, waits for its listener, then execs the fuzz supervisor.
#
# Required env vars (set by the launcher):
#   FARM_ROOT            root of this farm's private tree, e.g. /var/tmp/cm_farms/farm_00
#   FARM_HOSTNAME        hostname to set in the UTS namespace, e.g. cmfarm00
#   CODEMETER_BIN        path to CodeMeterLin, e.g. /usr/sbin/CodeMeterLin
#   SUPERVISOR           path to samc_light_supervisor.py
#   SUPERVISOR_OUT_DIR   where the supervisor writes its output tree
#   AX_FUZZ              path to the ax_fuzz repo (for samc_fuzz import)
#   WORKERS              supervisor --workers
#   SEED_BASE            supervisor --seed-base (hex ok, e.g. 0xC0000000)
#   MODE                 supervisor --mode
#   ITERATIONS           supervisor --iterations
#   TIMEOUT              supervisor --timeout (seconds)
#   RING_SIZE            supervisor --ring-size
#   PORT                 TCP port CodeMeterLin binds inside this net namespace
#   READY_FILE           touched once the daemon is listening
#   DAEMON_LOG           CodeMeterLin stdout/stderr is redirected here
#
# Do NOT run this script directly on the host. It expects to be inside a
# freshly-unshared set of namespaces — running it on the host would rebind
# system directories over their live mounts.

set -euo pipefail

: "${FARM_ROOT:?}"
: "${FARM_HOSTNAME:?}"
: "${CODEMETER_BIN:?}"
: "${SUPERVISOR:?}"
: "${SUPERVISOR_OUT_DIR:?}"
: "${AX_FUZZ:?}"
: "${WORKERS:?}"
: "${SEED_BASE:?}"
: "${MODE:?}"
: "${ITERATIONS:=10000000}"
: "${TIMEOUT:=900}"
: "${RING_SIZE:=100}"
: "${PORT:=22350}"
: "${READY_FILE:?}"
: "${DAEMON_LOG:?}"

# Safety: after unshare --fork --pid, this shell is PID 1 inside the new PID namespace.
if [ "$$" != "1" ]; then
    echo "ERROR: not running as PID 1; refusing to remount system directories" >&2
    exit 2
fi

hostname "$FARM_HOSTNAME" || true

# Make our mount namespace's propagation private so later bind/tmpfs mounts
# don't leak back to the host mount namespace.
mount --make-rprivate /

mount --bind "$FARM_ROOT/etc/wibu/CodeMeter" /etc/wibu/CodeMeter
mount --bind "$FARM_ROOT/var/lib/CodeMeter" /var/lib/CodeMeter
mount --bind "$FARM_ROOT/var/log/CodeMeter" /var/log/CodeMeter
mount --bind "$FARM_ROOT/run/lock"          /run/lock
mount --bind "$FARM_ROOT/var/tmp/cm_cores"  /var/tmp/cm_cores
# /tmp and /dev/shm must be private tmpfs: /tmp/cm_lock is a cross-process
# singleton and /dev/shm/CME-* files collide across instances.
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /dev/shm

ip link set lo up

ulimit -c unlimited
echo 0xff > /proc/self/coredump_filter 2>/dev/null || true

cd "$FARM_ROOT/work"

runuser -u daemon -- "$CODEMETER_BIN" -f > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Poll for the listener. ss inside this netns only sees this farm's daemon.
READY=0
for _ in $(seq 1 120); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "ERROR: CodeMeterLin (pid=$DAEMON_PID) exited before listener came up; see $DAEMON_LOG" >&2
        exit 3
    fi
    if ss -tln "( sport = :$PORT )" 2>/dev/null | grep -q ":$PORT"; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ "$READY" != "1" ]; then
    echo "ERROR: listener did not come up on :$PORT within 60s" >&2
    kill "$DAEMON_PID" 2>/dev/null || true
    exit 4
fi

touch "$READY_FILE"
echo "[$FARM_HOSTNAME] daemon_pid=$DAEMON_PID listening on :$PORT" >&2

# exec so the supervisor becomes PID 1 in the namespace; when it exits,
# the kernel tears down the whole namespace and CodeMeterLin with it.
SWEEP_BODY_LEN="${SWEEP_BODY_LEN:-712}"
SWEEP_BODY_SEED="${SWEEP_BODY_SEED:-0xB0D1E5}"
SWEEP_OPCODES="${SWEEP_OPCODES:-0x00-0xff}"
SWEEP_SKIP_OPCODES="${SWEEP_SKIP_OPCODES:-}"
SWEEP_PREFIX_ZERO_BYTES="${SWEEP_PREFIX_ZERO_BYTES:-0}"
SWEEP_PATCH_SID="${SWEEP_PATCH_SID:-0}"
SWEEP_BODY_LENGTHS="${SWEEP_BODY_LENGTHS:-}"

PATCH_SID_FLAG=()
if [ "$SWEEP_PATCH_SID" = "1" ]; then PATCH_SID_FLAG=(--sweep-patch-sid); fi

exec python3 "$SUPERVISOR" \
    --ax-fuzz                  "$AX_FUZZ" \
    --out-dir                  "$SUPERVISOR_OUT_DIR" \
    --host                     127.0.0.1 \
    --port                     "$PORT" \
    --workers                  "$WORKERS" \
    --mode                     "$MODE" \
    --iterations               "$ITERATIONS" \
    --ring-size                "$RING_SIZE" \
    --seed-base                "$SEED_BASE" \
    --timeout                  "$TIMEOUT" \
    --sweep-body-len           "$SWEEP_BODY_LEN" \
    --sweep-body-seed          "$SWEEP_BODY_SEED" \
    --sweep-opcodes            "$SWEEP_OPCODES" \
    --sweep-skip-opcodes       "$SWEEP_SKIP_OPCODES" \
    --sweep-prefix-zero-bytes  "$SWEEP_PREFIX_ZERO_BYTES" \
    --sweep-body-lengths       "$SWEEP_BODY_LENGTHS" \
    "${PATCH_SID_FLAG[@]}" \
    --no-service-check \
    --core-dir                 /var/tmp/cm_cores
