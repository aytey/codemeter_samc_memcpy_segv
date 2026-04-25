#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFLPP_ROOT="${AFLPP_ROOT:-/home/avj/clones/AFLplusplus}"
HARNESS_SO="${ROOT}/preload/cm_afl_harness.so"

MODE="${1:?usage: $0 MODE [INPUT [OUT]]}"
shift || true

case "${MODE}" in
  net_get_servers) INST_RANGES_DEFAULT="0x548000-0x889000" ;;
  net_*)
    INST_RANGES_DEFAULT="0x564000-0xbf1000"
    ;;
  *) echo "unknown net mode: ${MODE}" >&2; exit 2 ;;
esac

CORPUS_DIR="${ROOT}/seeds/cm_afl_${MODE}"
INPUT="${1:-${CORPUS_DIR}/base.bin}"
OUT="${2:-/tmp/cm_afl_${MODE}.showmap}"
TIMEOUT_MS="${TIMEOUT_MS:-8000}"
INST_RANGES="${AFL_QEMU_INST_RANGES:-${INST_RANGES_DEFAULT}}"
WAS_ACTIVE="$(systemctl is-active codemeter || true)"

cleanup() {
  if [[ "${WAS_ACTIVE}" == "active" ]]; then
    sudo -n systemctl start codemeter >/dev/null 2>&1 || true
  fi
  sudo -n systemctl reset-failed codemeter >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${ROOT}/scripts/rebuild_cm_afl_net_assets.sh" >/dev/null
"${ROOT}/scripts/build_cm_afl_harness.sh" >/dev/null
python3 "${ROOT}/scripts/build_cm_afl_net_corpus.py" "${MODE}" "${CORPUS_DIR}" >/dev/null

if [[ ! -f "${INPUT}" ]]; then
  INPUT="$(find "${CORPUS_DIR}" -maxdepth 1 -type f | sort | head -n 1)"
fi

mkdir -p "$(dirname "${OUT}")"
sudo -n rm -f "${OUT}" >/dev/null 2>&1 || true

sudo -n systemctl stop codemeter >/dev/null 2>&1 || true
sudo -n systemctl reset-failed codemeter >/dev/null 2>&1 || true

set +e
sudo -n runuser -u daemon -- bash -lc "
  umask 022
  exec env \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/var/lib/CodeMeter \
    USER=daemon \
    LOGNAME=daemon \
    AFL_PRELOAD='${HARNESS_SO}' \
    CM_AFL_HARNESS_MODE='${MODE}' \
    AFL_QEMU_INST_RANGES='${INST_RANGES}' \
    '${AFLPP_ROOT}/afl-showmap' \
    -Q \
    -t '${TIMEOUT_MS}' \
    -m none \
    -o '${OUT}' \
    -- \
    /usr/sbin/CodeMeterLin '${INPUT}'
"
rc=$?
set -e

echo "rc=${rc}"
test -f "${OUT}" && wc -l "${OUT}"
