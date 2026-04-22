#!/bin/bash
# samc_veth_target_init.sh
#
# Runs as PID 1 inside:
#
#   ip netns exec <ns> unshare --fork --kill-child=SIGINT \
#     --pid --mount-proc --mount --ipc --uts bash samc_veth_target_init.sh
#
# Unlike fuzz_farm_namespace_init.sh, this script starts only CodeMeterLin.
# The fuzzer stays outside the target network namespace and connects over the
# veth address, so CodeMeterLin sees the SAMC peer as non-loopback.

set -euo pipefail

: "${FARM_ROOT:?}"
: "${FARM_HOSTNAME:?}"
: "${CODEMETER_BIN:?}"
: "${PORT:=22350}"
: "${READY_FILE:?}"
: "${DAEMON_LOG:?}"

if [ "$$" != "1" ]; then
    echo "ERROR: not running as PID 1; refusing to remount system directories" >&2
    exit 2
fi

hostname "$FARM_HOSTNAME" || true

mount --make-rprivate /

mount --bind "$FARM_ROOT/etc/wibu/CodeMeter" /etc/wibu/CodeMeter
mount --bind "$FARM_ROOT/var/lib/CodeMeter" /var/lib/CodeMeter
mount --bind "$FARM_ROOT/var/log/CodeMeter" /var/log/CodeMeter
mount --bind "$FARM_ROOT/run/lock"          /run/lock
mount --bind "$FARM_ROOT/var/tmp/cm_cores"  /var/tmp/cm_cores
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /dev/shm

ip link set lo up

ulimit -c unlimited
echo 0xff > /proc/self/coredump_filter 2>/dev/null || true

cd "$FARM_ROOT/work"

runuser -u daemon -- "$CODEMETER_BIN" -f > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

cleanup() {
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup INT TERM

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
    cleanup
    exit 4
fi

touch "$READY_FILE"
echo "[$FARM_HOSTNAME] daemon_pid=$DAEMON_PID listening on :$PORT" >&2

wait "$DAEMON_PID"
RC=$?
echo "[$FARM_HOSTNAME] CodeMeterLin exited rc=$RC" >&2
exit "$RC"
