#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"

exec sudo -n python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes net_access net_access2 net_version net_info_system net_info_version net_get_servers \
  --workers-per-mode 1 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --wall-clock 1800 \
  --root /var/tmp/cm_afl_netns_smoke6 \
  --out-root "/home/avj/clones/ax_fuzz/output/cm_afl_netns_smoke6_${STAMP}"
