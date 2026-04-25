#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec "${ROOT}/fuzzer/run_cm_afl_netns_group.sh" \
  cm_afl_netns_weekend9_stateful_access \
  net_access_public_key \
  net_access_calc_sig \
  net_access_crypt2 \
  net_access_validate_signedtime \
  net_access_validate_signedlist \
  net_access_validate_deletefi \
  net_access_lt_create_context \
  net_access_lt_import_update \
  net_access_lt_cleanup
