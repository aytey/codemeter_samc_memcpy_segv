#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"

MODES=(
  net_access_public_key
  net_access_calc_sig
  net_access_crypt2
  net_access_validate_signedtime
  net_access_lt_create_context
  net_access_lt_import_update
  net_access2_public_key
  net_access2_calc_sig
  net_access2_crypt2
  net_access2_validate_signedtime
  net_access2_lt_create_context
  net_access2_lt_import_update
)

exec sudo -n python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes "${MODES[@]}" \
  --workers-per-mode 2 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --wall-clock 172800 \
  --root /var/tmp/cm_afl_netns_weekend12_stateful \
  --out-root "/home/avj/clones/ax_fuzz/output/cm_afl_netns_weekend12_stateful_${STAMP}"
