#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/preload/cm_afl_harness.so"

if [[ -x "${ROOT}/scripts/rebuild_cm_afl_native_assets.sh" ]]; then
  "${ROOT}/scripts/rebuild_cm_afl_native_assets.sh" >/dev/null
fi
if [[ -x "${ROOT}/scripts/rebuild_cm_afl_net_assets.sh" && -d /tmp/cm_sdk_api_sweep/frames ]]; then
  "${ROOT}/scripts/rebuild_cm_afl_net_assets.sh" >/dev/null
fi

gcc -shared -fPIC -O2 -Wall -Wextra -o "${OUT}" \
  "${ROOT}/preload/cm_afl_harness.c" -ldl -lpthread -lcrypto -lz

echo "${OUT}"
