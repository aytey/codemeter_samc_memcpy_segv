#!/bin/bash
# Launch a 6-hour daemon-to-server protocol fuzz campaign over local veth farms.
#
# Environment overrides:
#   FARMS=8
#   WORKERS_PER_FARM=8
#   WALL_CLOCK=21600
#   TIMEOUT=21600
#   RING_SIZE=200
#   DS_MODES=ds_mixed
#   DS_HELPER_DIR=/home/avj/clones/ax_decrypt/009/research_scripts
#   LOG_DIR=/home/avj/clones/ax_fuzz/output/veth_ds_6h_logs

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

FARMS="${FARMS:-8}"
WORKERS_PER_FARM="${WORKERS_PER_FARM:-8}"
WALL_CLOCK="${WALL_CLOCK:-21600}"
TIMEOUT="${TIMEOUT:-21600}"
RING_SIZE="${RING_SIZE:-200}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
DS_MODES="${DS_MODES:-ds_mixed}"
DS_HELPER_DIR="${DS_HELPER_DIR:-/home/avj/clones/ax_decrypt/009/research_scripts}"
LOG_DIR="${LOG_DIR:-/home/avj/clones/ax_fuzz/output/veth_ds_6h_logs}"

mkdir -p "$LOG_DIR"
LOG_PATH="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).log"

cd "$REPO_ROOT"

echo "log=$LOG_PATH"
echo "farms=$FARMS workers_per_farm=$WORKERS_PER_FARM wall_clock=$WALL_CLOCK timeout=$TIMEOUT"
echo "modes=$DS_MODES helper_dir=$DS_HELPER_DIR"

nohup sudo -n python3 fuzzer/samc_veth_farm_launcher.py \
  --farms "$FARMS" \
  --workers-per-farm "$WORKERS_PER_FARM" \
  --modes "$DS_MODES" \
  --ds-helper-dir "$DS_HELPER_DIR" \
  --wall-clock "$WALL_CLOCK" \
  --timeout "$TIMEOUT" \
  --ready-timeout "$READY_TIMEOUT" \
  --ring-size "$RING_SIZE" \
  --replace-existing \
  > "$LOG_PATH" 2>&1 &

PID=$!
echo "pid=$PID"
echo "tail -f $LOG_PATH"
