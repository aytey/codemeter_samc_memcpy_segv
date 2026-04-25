#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFLPP_ROOT="${AFLPP_ROOT:-/home/avj/clones/AFLplusplus}"
HARNESS_SO="${ROOT}/preload/cm_afl_harness.so"
MODE="${1:?usage: $0 MODE [OUT_DIR] [AFL_ROLE] [WORKER_ID]}"
shift || true

case "${MODE}" in
  net_get_servers) INST_RANGES_DEFAULT="0x548000-0x889000" ;;
  net_*)
    INST_RANGES_DEFAULT="0x564000-0xbf1000"
    ;;
  *) echo "unknown net mode: ${MODE}" >&2; exit 2 ;;
esac

STAMP="$(date +%Y%m%d_%H%M%S)"
DEFAULT_BASE="${ROOT}/output"
FALLBACK_BASE="/home/avj/clones/ax_fuzz/output"

if [[ -w "${DEFAULT_BASE}" ]]; then
  OUT_BASE="${DEFAULT_BASE}"
elif [[ -d "${FALLBACK_BASE}" && -w "${FALLBACK_BASE}" ]]; then
  OUT_BASE="${FALLBACK_BASE}"
else
  OUT_BASE="/tmp"
fi

OUT_DIR="${1:-${OUT_BASE}/cm_afl_${MODE}_${STAMP}}"
shift || true
AFL_ROLE="${1:-M}"
shift || true
WORKER_ID="${1:-${MODE}_main}"
CORPUS_DIR="${ROOT}/seeds/cm_afl_${MODE}"
LOG="${OUT_DIR}/afl.log"
PIDFILE="${OUT_DIR}/afl.pid"
TIMEOUT_MS="${TIMEOUT_MS:-8000+}"
INST_RANGES="${AFL_QEMU_INST_RANGES:-${INST_RANGES_DEFAULT}}"

"${ROOT}/scripts/rebuild_cm_afl_net_assets.sh" >/dev/null
"${ROOT}/scripts/build_cm_afl_harness.sh" >/dev/null
python3 "${ROOT}/scripts/build_cm_afl_net_corpus.py" "${MODE}" "${CORPUS_DIR}" >/dev/null

mkdir -p "${OUT_DIR}"
chmod 0777 "${OUT_DIR}"

ROLE_ARGS=""
case "${AFL_ROLE}" in
  M) ROLE_ARGS="-M '${WORKER_ID}'" ;;
  S) ROLE_ARGS="-S '${WORKER_ID}'" ;;
  none|"") ROLE_ARGS="" ;;
  *) echo "AFL_ROLE must be M, S, or none" >&2; exit 2 ;;
esac

if [[ "${AFL_ROLE}" != "none" && -n "${WORKER_ID}" ]]; then
  LOG="${OUT_DIR}/afl_${WORKER_ID}.log"
  PIDFILE="${OUT_DIR}/afl_${WORKER_ID}.pid"
fi

setsid bash -lc "
  set -euo pipefail
  WAS_ACTIVE=\"\$(systemctl is-active codemeter || true)\"
  cleanup() {
    if [[ \"\${WAS_ACTIVE}\" == \"active\" ]]; then
      sudo -n systemctl start codemeter >/dev/null 2>&1 || true
    fi
    sudo -n systemctl reset-failed codemeter >/dev/null 2>&1 || true
  }
  child_pid=''
  perms_pid=''
  on_exit() {
    trap - EXIT INT TERM
    if [[ -n \"\${perms_pid}\" ]]; then
      kill \"\${perms_pid}\" >/dev/null 2>&1 || true
      wait \"\${perms_pid}\" >/dev/null 2>&1 || true
    fi
    if [[ -n \"\${child_pid}\" ]]; then
      kill \"\${child_pid}\" >/dev/null 2>&1 || true
      wait \"\${child_pid}\" >/dev/null 2>&1 || true
    fi
    cleanup
  }
  trap on_exit EXIT INT TERM
  sudo -n systemctl stop codemeter >/dev/null 2>&1 || true
  sudo -n systemctl reset-failed codemeter >/dev/null 2>&1 || true
  sudo -n runuser -u daemon -- bash -lc \"
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
      ${ROLE_ARGS} \
      -i '${CORPUS_DIR}' \
      -o '${OUT_DIR}/sync' \
      -- \
      /usr/sbin/CodeMeterLin @@ \
      >'${LOG}' 2>&1 < /dev/null
  \" &
  child_pid=\$!
  (
    while kill -0 \"\${child_pid}\" >/dev/null 2>&1; do
      sudo -n chmod -R a+rX '${OUT_DIR}/sync' >/dev/null 2>&1 || true
      sleep 2
    done
  ) &
  perms_pid=\$!
  wait \"\${child_pid}\"
" &

echo $! > "${PIDFILE}"
echo "mode=${MODE}"
echo "out_dir=${OUT_DIR}"
echo "log=${LOG}"
echo "pid=$(cat "${PIDFILE}")"
