#!/bin/bash
# Single-worker veth-farm confirmation run for one (mode, opcode, prefix_len) candidate.
#
# The 8h ECDH prefix run races 8 workers per target; some attribution candidates
# are bystanders. This script re-runs a single narrowed candidate in isolation
# to tell a genuine crash from a racing bystander.
#
# Usage (must run as root):
#   sudo ./run_confirm_candidate.sh hello 0x5e 5
#   sudo ./run_confirm_candidate.sh ack   0x5e 14
#   sudo ./run_confirm_candidate.sh ack   0x5e 15
#   sudo ./run_confirm_candidate.sh hello 0x22 2
#
# Optional env overrides:
#   WALL_CLOCK=120   TIMEOUT=120   ITERATIONS=50000
#   RING_SIZE=50     SEED_BASE=0xE0000000
#   OUT_ROOT=/home/avj/clones/ax_fuzz/output/confirm_runs

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-hello}"
OPCODE="${2:-0x5e}"
PREFIX_LEN="${3:-5}"
WALL_CLOCK="${WALL_CLOCK:-120}"
TIMEOUT="${TIMEOUT:-120}"
ITERATIONS="${ITERATIONS:-50000}"
RING_SIZE="${RING_SIZE:-50}"
SEED_BASE="${SEED_BASE:-0xE0000000}"
OUT_ROOT="${OUT_ROOT:-/home/avj/clones/ax_fuzz/output/confirm_runs}"

if [[ "$MODE" != "hello" && "$MODE" != "ack" ]]; then
    echo "usage: $0 [hello|ack] <opcode_hex> <prefix_len>" >&2
    exit 1
fi

ECDH_MODE="ecdh_prefix_${MODE}"
TS="$(date +%Y%m%d_%H%M%S)"
TAG="${MODE}_op${OPCODE/0x/}_len${PREFIX_LEN}"
LOG_DIR="${OUT_ROOT}/confirm_${TAG}_${TS}"
LOG_PATH="${LOG_DIR}/launcher.log"

mkdir -p "$LOG_DIR"

echo "confirm: mode=${MODE} opcode=${OPCODE} prefix_len=${PREFIX_LEN}"
echo "ecdh_mode=${ECDH_MODE} wall_clock=${WALL_CLOCK} timeout=${TIMEOUT}"
echo "out=${LOG_DIR}"
echo "log=${LOG_PATH}"

cd "$REPO_ROOT"

# Run synchronously so exit code reflects crash vs clean finish.
sudo python3 fuzzer/samc_veth_farm_launcher.py \
  --farms 1 \
  --workers-per-farm 1 \
  --modes "${ECDH_MODE}" \
  --ecdh-prefix-opcodes "${OPCODE}" \
  --ecdh-prefix-lengths "${PREFIX_LEN}" \
  --ecdh-prefix-include-known-every 0 \
  --iterations "${ITERATIONS}" \
  --ring-size "${RING_SIZE}" \
  --seed-base-origin "${SEED_BASE}" \
  --wall-clock "${WALL_CLOCK}" \
  --timeout "${TIMEOUT}" \
  --out-root "${LOG_DIR}" \
  --replace-existing \
  2>&1 | tee "${LOG_PATH}"

RC=${PIPESTATUS[0]}
echo "done rc=${RC} out=${LOG_DIR}"
