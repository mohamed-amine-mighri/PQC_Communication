#!/usr/bin/env bash
set -euo pipefail

PY="$HOME/pqc/ppk2-api-python/.venv/bin/python"
SCRIPT="$HOME/pqc/PQC_Communication/Signature-Argon/tools/energy/run_ppk2_bench_argon.py"
OUT="$HOME/pqc/PQC_Communication/Signature-Argon/results/energy/argon_energy.jsonl"

ARGON_PORT="/dev/ttyACM0"
FIRMWARE_BIN="$(ls -t "$HOME/pqc/PQC_Communication/Signature-Argon"/argon_firmware_*.bin | head -n 1)"

ALGOS=(
ML_DSA_44
)

OPS=(
keypair
)

detect_ppk_port() {
  "$PY" - <<'PY'
from ppk2_api.ppk2_api import PPK2_API
devices = PPK2_API.list_devices()
if not devices:
    raise SystemExit("No PPK2 detected")
print(devices[0][0])
PY
}

flash_once() {
  echo
  echo "============================================================"
  echo "[FLASH] Using firmware: $FIRMWARE_BIN"
  echo "============================================================"
  particle flash --usb "$FIRMWARE_BIN"
  sleep 3
}

run_case() {
  local ALG="$1"
  local OP="$2"
  local PPK_PORT
  PPK_PORT="$(detect_ppk_port)"

  echo
  echo "============================================================"
  echo "[RUN] ALG=$ALG OP=$OP"
  echo "[RUN] PPK_PORT=$PPK_PORT ARGON_PORT=$ARGON_PORT"
  echo "============================================================"

  "$PY" "$SCRIPT" \
    --ppk-port "$PPK_PORT" \
    --serial-port "$ARGON_PORT" \
    --platform argon-local \
    --alg "$ALG" \
    --op "$OP" \
    --output "$OUT" \
    --flash-cmd ""
}

mkdir -p "$HOME/pqc/PQC_Communication/Signature-Argon/results/energy"

flash_once

for ALG in "${ALGOS[@]}"; do
  for OP in "${OPS[@]}"; do
    run_case "$ALG" "$OP"
    sleep 2
  done
done

echo
echo "Batch finished."
echo "Results: $OUT"