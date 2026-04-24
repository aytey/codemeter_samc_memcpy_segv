#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFLPP_ROOT="${AFLPP_ROOT:-/home/avj/clones/AFLplusplus}"
HARNESS_SO="${ROOT}/preload/cm_afl_harness.so"
MODE="${1:?usage: $0 MODE [OUT_DIR] [AFL_ROLE] [WORKER_ID]}"
shift || true

case "${MODE}" in
  bef830) INST_RANGES_DEFAULT="0xbeeac0-0xbf0000" ;;
  7f9060) INST_RANGES_DEFAULT="0x7f9000-0x7fe800" ;;
  54ace0) INST_RANGES_DEFAULT="0x54ace0-0x553300" ;;
  *) echo "unknown mode: ${MODE}" >&2; exit 2 ;;
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

OUT_DIR="${1:-${OUT_BASE}/cm_afl_native_${MODE}_${STAMP}}"
shift || true
AFL_ROLE="${1:-M}"
shift || true
WORKER_ID="${1:-${MODE}_main}"
CORPUS_DIR="${ROOT}/seeds/cm_afl_native_${MODE}"
LOG="${OUT_DIR}/afl.log"
PIDFILE="${OUT_DIR}/afl.pid"
TIMEOUT_MS="${TIMEOUT_MS:-5000+}"
INST_RANGES="${AFL_QEMU_INST_RANGES:-${INST_RANGES_DEFAULT}}"

"${ROOT}/scripts/build_cm_afl_harness.sh" >/dev/null
python3 "${ROOT}/scripts/build_cm_afl_native_corpus.py" "${MODE}" "${CORPUS_DIR}" >/dev/null

mkdir -p "${OUT_DIR}"

ROLE_ARGS=""
case "${AFL_ROLE}" in
  M) ROLE_ARGS="-M '${WORKER_ID}'" ;;
  S) ROLE_ARGS="-S '${WORKER_ID}'" ;;
  none|"") ROLE_ARGS="" ;;
  *) echo "AFL_ROLE must be M, S, or none" >&2; exit 2 ;;
esac

setsid bash -lc "
  exec env \
    -u LD_PRELOAD \
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
" &

echo $! > "${PIDFILE}"
echo "mode=${MODE}"
echo "out_dir=${OUT_DIR}"
echo "log=${LOG}"
echo "pid=$(cat "${PIDFILE}")"
