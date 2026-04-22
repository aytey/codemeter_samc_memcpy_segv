#!/bin/bash
# Launch a 6-hour ECDH prefix/dispatcher fuzz campaign over local veth farms.
# Covers only application→daemon messages (HELLO and ACK over the ECDH 0xa1
# channel); no daemon→server records.  Use run_ds_6h.sh for those.
#
# Environment overrides:
#   FARMS=8
#   WORKERS_PER_FARM=8
#   WALL_CLOCK=21600
#   TIMEOUT=21600
#   RING_SIZE=200
#   ECDH_PREFIX_OPCODES=0x00-0xff
#   ECDH_PREFIX_LENGTHS=1-32
#   ECDH_PREFIX_INCLUDE_KNOWN_EVERY=0
#   LOG_DIR=/home/avj/clones/ax_fuzz/output/veth_prefix_6h_logs

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

FARMS="${FARMS:-8}"
WORKERS_PER_FARM="${WORKERS_PER_FARM:-8}"
WALL_CLOCK="${WALL_CLOCK:-21600}"
TIMEOUT="${TIMEOUT:-21600}"
RING_SIZE="${RING_SIZE:-200}"
READY_TIMEOUT="${READY_TIMEOUT:-120}"
ECDH_PREFIX_OPCODES="${ECDH_PREFIX_OPCODES:-0x00-0xff}"
ECDH_PREFIX_LENGTHS="${ECDH_PREFIX_LENGTHS:-1-32}"
ECDH_PREFIX_INCLUDE_KNOWN_EVERY="${ECDH_PREFIX_INCLUDE_KNOWN_EVERY:-0}"
LOG_DIR="${LOG_DIR:-/home/avj/clones/ax_fuzz/output/veth_prefix_6h_logs}"

mkdir -p "$LOG_DIR"
LOG_PATH="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).log"

cd "$REPO_ROOT"

echo "log=$LOG_PATH"
echo "farms=$FARMS workers_per_farm=$WORKERS_PER_FARM wall_clock=$WALL_CLOCK timeout=$TIMEOUT"
echo "opcodes=$ECDH_PREFIX_OPCODES prefix_lengths=$ECDH_PREFIX_LENGTHS include_known_every=$ECDH_PREFIX_INCLUDE_KNOWN_EVERY"

nohup sudo -n python3 fuzzer/samc_veth_farm_launcher.py \
  --farms "$FARMS" \
  --workers-per-farm "$WORKERS_PER_FARM" \
  --modes ecdh_prefix_hello,ecdh_prefix_ack \
  --ecdh-prefix-opcodes "$ECDH_PREFIX_OPCODES" \
  --ecdh-prefix-lengths "$ECDH_PREFIX_LENGTHS" \
  --ecdh-prefix-include-known-every "$ECDH_PREFIX_INCLUDE_KNOWN_EVERY" \
  --wall-clock "$WALL_CLOCK" \
  --timeout "$TIMEOUT" \
  --ready-timeout "$READY_TIMEOUT" \
  --ring-size "$RING_SIZE" \
  --replace-existing \
  > "$LOG_PATH" 2>&1 &

PID=$!
echo "pid=$PID"
echo "tail -f $LOG_PATH"
