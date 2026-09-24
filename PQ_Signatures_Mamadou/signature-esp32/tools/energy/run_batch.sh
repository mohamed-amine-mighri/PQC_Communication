#!/usr/bin/env bash
set -euo pipefail

PY="$HOME/pqc/ppk2-api-python/.venv/bin/python"
SCRIPT="$HOME/pqc/signature-esp32/tools/energy/run_ppk2_bench.py"
OUT="$HOME/pqc/signature-esp32/results/energy/esp32_energy.jsonl"

ESP_PORT="/dev/ttyUSB0"

ALGOS=(
FALCON_512
# FALCON_1024
# FALCON_PADDED_512
# FALCON_PADDED_1024
# ML_DSA_44
# ML_DSA_65
# ML_DSA_87
# SPHINCS_SHA2_128F
# SPHINCS_SHA2_128S
# SPHINCS_SHA2_192F
# SPHINCS_SHA2_192S
# SPHINCS_SHA2_256F
# SPHINCS_SHA2_256S
# SPHINCS_SHAKE_128F
# SPHINCS_SHAKE_128S
# SPHINCS_SHAKE_192F
# SPHINCS_SHAKE_192S
# SPHINCS_SHAKE_256F
# SPHINCS_SHAKE_256S
# RSA_2048
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

run_case () {
  local ALG="$1"
  local OP="$2"
  local KPI="$3"
  local SVI="$4"
  local WHI="$5"

  local PPK_PORT
  PPK_PORT="$(detect_ppk_port)"

  echo
  echo "============================================================"
  echo "[RUN] ALG=$ALG OP=$OP KPI=$KPI SVI=$SVI WHI=$WHI"
  echo "[RUN] PPK_PORT=$PPK_PORT ESP_PORT=$ESP_PORT"
  echo "============================================================"

  lsof "$ESP_PORT" || true

  "$PY" "$SCRIPT" \
    --ppk-port "$PPK_PORT" \
    --platform esp32-local \
    --alg "$ALG" \
    --op "$OP" \
    --output "$OUT" \
    --cmd "bash -lc 'source ~/Téléchargements/esp-idf/export.sh && cd ~/pqc/signature-esp32 && idf.py -p $ESP_PORT -D BENCH_ALG=$ALG -D BENCH_OP=$OP -D KEYPAIR_ITERS=$KPI -D SV_ITERS=$SVI -D WHOLE_ITERS=$WHI build flash monitor'"

  sleep 2
}

mkdir -p "$HOME/pqc/signature-esp32/results/energy"

pkill -f idf.py || true
pkill -f idf_monitor.py || true
pkill -f monitor || true
sleep 1

for ALG in "${ALGOS[@]}"; do
  run_case "$ALG" keypair 5 0 0
  run_case "$ALG" sign 0 5 0
  run_case "$ALG" verify 0 5 0
  run_case "$ALG" whole 0 0 5
done

echo
echo "Batch finished."
echo "Results: $OUT"