#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AFLPP_ROOT="${AFLPP_ROOT:-/home/avj/clones/AFLplusplus}"
HARNESS_SO="${ROOT}/preload/cm_afl_harness.so"

MODE="${1:?usage: $0 MODE [INPUT [OUT]]}"
shift || true

case "${MODE}" in
  bef830) INST_RANGES_DEFAULT="0xbeeac0-0xbf0000" ;;
  7f9060) INST_RANGES_DEFAULT="0x7f9000-0x7fe800" ;;
  54ace0) INST_RANGES_DEFAULT="0x54ace0-0x553300" ;;
  *) echo "unknown mode: ${MODE}" >&2; exit 2 ;;
esac

CORPUS_DIR="${ROOT}/seeds/cm_afl_native_${MODE}"
INPUT="${1:-${CORPUS_DIR}/small.bin}"
OUT="${2:-/tmp/cm_afl_native_${MODE}.showmap}"
TIMEOUT_MS="${TIMEOUT_MS:-5000}"
INST_RANGES="${AFL_QEMU_INST_RANGES:-${INST_RANGES_DEFAULT}}"

"${ROOT}/scripts/build_cm_afl_harness.sh" >/dev/null
python3 "${ROOT}/scripts/build_cm_afl_native_corpus.py" "${MODE}" "${CORPUS_DIR}" >/dev/null

if [[ ! -f "${INPUT}" ]]; then
  INPUT="$(find "${CORPUS_DIR}" -maxdepth 1 -type f | sort | head -n 1)"
fi

mkdir -p "$(dirname "${OUT}")"
rm -f "${OUT}"
set +e
env \
  -u LD_PRELOAD \
  AFL_PRELOAD="${HARNESS_SO}" \
  CM_AFL_HARNESS_MODE="${MODE}" \
  AFL_QEMU_INST_RANGES="${INST_RANGES}" \
  "${AFLPP_ROOT}/afl-showmap" \
  -Q \
  -t "${TIMEOUT_MS}" \
  -m none \
  -o "${OUT}" \
  -- \
  /usr/sbin/CodeMeterLin "${INPUT}"
rc=$?
set -e
echo "rc=${rc}"
test -f "${OUT}" && wc -l "${OUT}"
