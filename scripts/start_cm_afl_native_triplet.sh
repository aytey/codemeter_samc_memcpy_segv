#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

BASE_DIR="${1:-${OUT_BASE}/cm_afl_native_triplet_${STAMP}}"
mkdir -p "${BASE_DIR}"

for mode in bef830 7f9060 54ace0; do
  bash "${ROOT}/scripts/start_cm_afl_native_qemu.sh" "${mode}" "${BASE_DIR}/${mode}" M "${mode}_main"
done

echo "base_dir=${BASE_DIR}"
