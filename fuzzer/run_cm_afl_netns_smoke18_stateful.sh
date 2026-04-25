#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"

MODES=(
  net_access_public_key
  net_access_calc_sig
  net_access_crypt2
  net_access_validate_signedtime
  net_access_validate_signedlist
  net_access_validate_deletefi
  net_access_lt_create_context
  net_access_lt_import_update
  net_access_lt_cleanup
  net_access2_public_key
  net_access2_calc_sig
  net_access2_crypt2
  net_access2_validate_signedtime
  net_access2_validate_signedlist
  net_access2_validate_deletefi
  net_access2_lt_create_context
  net_access2_lt_import_update
  net_access2_lt_cleanup
)

exec sudo -n python3 "${ROOT}/fuzzer/cm_afl_netns_launcher.py" \
  --modes "${MODES[@]}" \
  --workers-per-mode 1 \
  --timeout-ms 300000+ \
  --max-retries 5 \
  --single-seed-name base.bin \
  --wall-clock 900 \
  --root /var/tmp/cm_afl_netns_smoke18_stateful \
  --out-root "/home/avj/clones/ax_fuzz/output/cm_afl_netns_smoke18_stateful_${STAMP}"
