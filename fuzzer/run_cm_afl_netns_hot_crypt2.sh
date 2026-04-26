#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"

export CM_AFL_NET_MUTATION_STYLE=structured

exec sudo -n --preserve-env=CM_AFL_NET_MUTATION_STYLE python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes net_access_crypt2 \
  --workers-per-mode 27 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --skip-build \
  --wall-clock 172800 \
  --root "/var/tmp/cm_afl_netns_hot_crypt2" \
  --out-root "/home/avj/clones/ax_fuzz/output/cm_afl_netns_hot_crypt2_${STAMP}"
