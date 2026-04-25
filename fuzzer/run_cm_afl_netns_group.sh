#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 OUT_PREFIX MODE..." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_PREFIX="$1"
shift
MODES=("$@")

exec sudo -n --preserve-env=CM_AFL_NET_MUTATION_STYLE python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes "${MODES[@]}" \
  --workers-per-mode 3 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --wall-clock 172800 \
  --root "/var/tmp/${OUT_PREFIX}" \
  --out-root "/home/avj/clones/ax_fuzz/output/${OUT_PREFIX}_${STAMP}"
