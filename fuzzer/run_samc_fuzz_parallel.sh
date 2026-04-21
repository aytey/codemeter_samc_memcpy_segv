#!/bin/bash
# run_samc_fuzz_parallel.sh — kick off N concurrent samc_fuzz.py instances
# against the live daemon, each with a unique seed and rotating which
# captured frame they primarily mutate.  Output goes under
# /home/avj/clones/ax_fuzz/output/samc_fuzz/worker_NN/.
#
# Usage:  WORKERS=16 ./run_samc_fuzz_parallel.sh
#         (defaults to 16 workers)

set -euo pipefail
: "${WORKERS:=16}"
: "${ITERATIONS:=10000000}"

REPO=/home/avj/clones/ax_fuzz
PY=/home/avj/clones/ax_fuzz/tier1/samc_fuzz.py
ROOT=$REPO/output/samc_fuzz_par

# Ensure daemon is up
if ! ss -tlnp 2>/dev/null | grep -q ":22350 "; then
    echo "ERROR: daemon not on :22350. Run: sudo systemctl start codemeter" >&2
    exit 1
fi

mkdir -p "$ROOT"

# 16 workers: rotate target_frame across {-1=rotate, 0, 1, 2}
# 4 of each kind for variety.
TARGETS=(-1 -1 -1 -1  0 0 0 0  1 1 1 1  2 2 2 2)
TAGS=(rot rot rot rot  hello hello hello hello  ack ack ack ack  big big big big)

for ((i=0; i<WORKERS; i++)); do
    seed=$((1000 + i * 31))
    tf=${TARGETS[$i]}
    tag=${TAGS[$i]}
    odir=$ROOT/w$(printf %02d $i)_${tag}
    mkdir -p "$odir"
    log=$odir/worker.log
    nohup python3 "$PY" \
        --iterations "$ITERATIONS" \
        --seed "$seed" \
        --target-frame "$tf" \
        --out-dir "$odir" \
        --log-every 200 \
        > "$log" 2>&1 &
    echo "  worker $i: tag=$tag seed=$seed tf=$tf -> pid $! ($odir)"
done

echo ""
echo "Spawned $WORKERS workers under $ROOT"
echo ""
echo "Watch progress:"
echo "  tail -f $ROOT/w*/worker.log"
echo "  ls $ROOT/*/crashes/ 2>/dev/null"
echo "  watch -n 5 'for d in $ROOT/w*; do tail -1 \$d/worker.log 2>/dev/null | head -c 120; echo; done'"
echo ""
echo "Stop:  pkill -f samc_fuzz.py"
