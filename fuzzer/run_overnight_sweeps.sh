#!/usr/bin/env bash
# Chain of four sweep variants, 8 farms x 12 workers each, ~3h per variant.
# Run as: sudo bash fuzzer/run_overnight_sweeps.sh
#
# Each variant produces its own timestamped out_root under
# /home/avj/clones/ax_fuzz/output/farms/. At the end, this script prints a
# one-line-per-variant summary of new-signature counts.
#
# Core policy: known-signature cores are deleted (no exemplars kept); new
# signatures are preserved. Disk stays flat unless something new actually
# crashes.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="$HERE/fuzz_farm_launcher.py"
LOG_ROOT="/tmp/overnight_sweeps"
mkdir -p "$LOG_ROOT"

FARMS=8
WORKERS=12
WALL_CLOCK=10800   # 3h per variant
PER_RUN_TIMEOUT=300
SKIP="0x5e,0x34"

run_variant() {
    local name="$1"; shift
    local log="$LOG_ROOT/${name}.log"
    local out_marker="$LOG_ROOT/${name}.out_root"
    echo "=== $(date -Iseconds) === variant=${name} start (${WALL_CLOCK}s) ===" | tee -a "$log"
    # Delete leftover cores before each variant so disk starts flat.
    find /var/tmp/cm_farms -path '*/var/tmp/cm_cores/core.CodeMeterLin.*' -delete 2>/dev/null || true
    PYTHONUNBUFFERED=1 python3 "$LAUNCHER" \
        --farms "$FARMS" --workers-per-farm "$WORKERS" \
        --modes sweep \
        --sweep-skip-opcodes "$SKIP" \
        --wall-clock "$WALL_CLOCK" --timeout "$PER_RUN_TIMEOUT" \
        "$@" >>"$log" 2>&1 || {
            echo "!!! variant ${name} exited non-zero" | tee -a "$log"
        }
    # Record the out_root the launcher used (latest farms/ dir).
    ls -1dt /home/avj/clones/ax_fuzz/output/farms/2026* | head -1 >"$out_marker"
    echo "=== $(date -Iseconds) === variant=${name} end (out=$(cat "$out_marker")) ===" | tee -a "$log"
}

# Variant A: transport-cleared, short — should reach opcode dispatch for
# most opcodes. 8B total = opcode + 3 zero bytes + 4-byte SID patch.
run_variant A_short \
    --sweep-prefix-zero-bytes 3 \
    --sweep-patch-sid \
    --sweep-body-len 8

# Variant B: transport-cleared, medium (40B). SID patched, then random tail.
run_variant B_medium \
    --sweep-prefix-zero-bytes 3 \
    --sweep-patch-sid \
    --sweep-body-len 40

# Variant C: transport-cleared, long (712B, matches captured BIG-frame size).
run_variant C_long \
    --sweep-prefix-zero-bytes 3 \
    --sweep-patch-sid \
    --sweep-body-len 712

# Variant D: length sweep across 10 sizes; every (opcode, length) combination
# gets exercised as workers cycle both dimensions independently.
run_variant D_lensweep \
    --sweep-prefix-zero-bytes 3 \
    --sweep-patch-sid \
    --sweep-body-lengths "4,8,12,16,24,40,100,200,400,712"

echo
echo "=== $(date -Iseconds) === all variants done ==="
for variant in A_short B_medium C_long D_lensweep; do
    out_marker="$LOG_ROOT/${variant}.out_root"
    [ -f "$out_marker" ] || continue
    out_root="$(cat "$out_marker")"
    report="$out_root/final_report.json"
    if [ -f "$report" ]; then
        python3 -c "
import json, sys
r = json.load(open('$report'))
buckets = r.get('buckets', {})
known = [k for k in buckets if k in ('memcpy_8f431d_prefixed_hello',)]
unknown = [k for k in buckets if k not in known]
print(f'{\"$variant\":<12} known={sum(buckets[k] for k in known)} unknown={sum(buckets[k] for k in unknown)} unknown_sigs={unknown}')
"
    else
        echo "$variant no final_report.json"
    fi
done
