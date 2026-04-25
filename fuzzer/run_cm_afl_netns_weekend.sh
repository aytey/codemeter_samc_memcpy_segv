#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"

exec sudo -n python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes net_get_servers net_info_version net_version \
  --workers-per-mode 6 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --wall-clock 216000 \
  --root /var/tmp/cm_afl_netns_weekend \
  --out-root "/home/avj/clones/ax_fuzz/output/cm_afl_netns_weekend_${STAMP}"
