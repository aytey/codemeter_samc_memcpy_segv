#!/bin/bash
# cm_afl_netns_init.sh
#
# Runs as PID 1 inside:
#   unshare --fork --kill-child=SIGINT --pid --mount-proc --mount --ipc --net --uts
#
# Sets up one isolated filesystem/net namespace for one AFL worker, then execs
# afl-fuzz under the daemon user. Each worker gets:
#   - private loopback namespace
#   - private /var/lib/CodeMeter, /var/log/CodeMeter, /run/lock, /tmp, /dev/shm
#   - shared host-visible AFL sync directory for queue synchronization

set -euo pipefail

: "${FARM_ROOT:?}"
: "${FARM_HOSTNAME:?}"
: "${CODEMETER_BIN:?}"
: "${AFLPP_ROOT:?}"
: "${HARNESS_SO:?}"
: "${MODE:?}"
: "${CORPUS_DIR:?}"
: "${SYNC_DIR:?}"
: "${WORKER_ID:?}"
: "${WORKER_ROLE:?}"
: "${WORKER_LOG:?}"
: "${READY_FILE:?}"
: "${INST_RANGES:?}"
: "${TIMEOUT_MS:=8000+}"

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

mkdir -p "$(dirname "$WORKER_LOG")" "$SYNC_DIR"
chmod 0777 "$(dirname "$WORKER_LOG")" "$SYNC_DIR" || true
cd "$FARM_ROOT/work"

case "$WORKER_ROLE" in
    M) ROLE_ARGS_STR="-M '$WORKER_ID'" ;;
    S) ROLE_ARGS_STR="-S '$WORKER_ID'" ;;
    none|"") ROLE_ARGS_STR="" ;;
    *) echo "ERROR: WORKER_ROLE must be M, S, or none" >&2; exit 3 ;;
esac

runuser -u daemon -- bash -lc "
    umask 022
    exec env \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin \
      HOME=/var/lib/CodeMeter \
      USER=daemon \
      LOGNAME=daemon \
      AFL_PRELOAD='${HARNESS_SO}' \
      CM_AFL_HARNESS_MODE='${MODE}' \
      AFL_SKIP_CPUFREQ=1 \
      AFL_NO_FORKSRV=1 \
      AFL_QEMU_INST_RANGES='${INST_RANGES}' \
      '${AFLPP_ROOT}/afl-fuzz' \
      -Q \
      -t '${TIMEOUT_MS}' \
      -m none \
      ${ROLE_ARGS_STR} \
      -i '${CORPUS_DIR}' \
      -o '${SYNC_DIR}' \
      -- \
      '${CODEMETER_BIN}' @@ \
      >'${WORKER_LOG}' 2>&1 < /dev/null
" &
AFL_PID=$!

cleanup() {
    kill "$AFL_PID" 2>/dev/null || true
    wait "$AFL_PID" 2>/dev/null || true
}
trap cleanup INT TERM

# Relax AFL-created perms so the host user can inspect stats and queues.
(
    while kill -0 "$AFL_PID" 2>/dev/null; do
        chmod -R a+rX "$SYNC_DIR" 2>/dev/null || true
        sleep 2
    done
) &
PERMS_PID=$!

WORKER_DIR="$SYNC_DIR/$WORKER_ID"
READY=0
for _ in $(seq 1 240); do
    if ! kill -0 "$AFL_PID" 2>/dev/null; then
        echo "ERROR: afl-fuzz exited before readiness; see $WORKER_LOG" >&2
        kill "$PERMS_PID" 2>/dev/null || true
        wait "$PERMS_PID" 2>/dev/null || true
        exit 4
    fi
    if [ -f "$WORKER_DIR/fuzzer_setup" ] || [ -f "$WORKER_DIR/fuzzer_stats" ]; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ "$READY" != "1" ]; then
    echo "ERROR: AFL worker did not become ready within 120s; see $WORKER_LOG" >&2
    kill "$PERMS_PID" 2>/dev/null || true
    wait "$PERMS_PID" 2>/dev/null || true
    cleanup
    exit 5
fi

touch "$READY_FILE"
echo "[$FARM_HOSTNAME] worker_id=$WORKER_ID ready" >&2

wait "$AFL_PID"
RC=$?
kill "$PERMS_PID" 2>/dev/null || true
wait "$PERMS_PID" 2>/dev/null || true
exit "$RC"
