#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "${ROOT}/scripts/build_cm_afl_net_assets.py" \
  --out "${ROOT}/preload/cm_afl_net_assets.h"
