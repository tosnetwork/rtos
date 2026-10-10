#!/usr/bin/env bash
set -euo pipefail

# One-button bootstrap for local singlehost + rtosctl service.
# Preconditions:
# - Place vault file at rtos/tests/test_run_net_py/vault.json (or override VAULT_FILE)
# - .env for rtos/tests/test_load_net must contain funded MASTER_WALLET_KEY

# SCRIPT_LOG=bootstrap RTOSCTL_LOG=rtosctl ./run_singlehost_rtosctl.sh

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
RUN_NET_DIR="$REPO_ROOT/rtos/tests/test_run_net_py"
LOAD_NET_DIR="$REPO_ROOT/rtos/tests/test_load_net"
TMP_DIR="$RUN_NET_DIR/tmp"
RTOSCTL_CONFIG="$TMP_DIR/rtosctl-local.json"
RTOSCTL_LOG_RAW="${RTOSCTL_LOG:-rtosctl-service.log}"
SCRIPT_LOG_RAW="${SCRIPT_LOG:-singlehost-bootstrap.log}"
VAULT_FILE="${VAULT_FILE:-$RUN_NET_DIR/vault.json}"

MASTER_TOPUP_TOS="${MASTER_TOPUP_TOS:-300}"
WALLET_TOPUP_TOS="${WALLET_TOPUP_TOS:-2000}"
POOL_TOPUP_TOS="${POOL_TOPUP_TOS:-50000}"
PARTICIPANTS_WAIT_SECONDS="${PARTICIPANTS_WAIT_SECONDS:-600}"
NOBUILD="${NOBUILD:-0}"
KEEP_RTOSCTL_ON_SUCCESS="${KEEP_RTOSCTL_ON_SUCCESS:-1}"
RTOSCTL_PID=""
INTERRUPTED=0

RTOSCTL_LOG_NAME="$(basename "$RTOSCTL_LOG_RAW")"
SCRIPT_LOG_NAME="$(basename "$SCRIPT_LOG_RAW")"

if [[ "$RTOSCTL_LOG_NAME" == *.log ]]; then
  RTOSCTL_LOG="$TMP_DIR/$RTOSCTL_LOG_NAME"
else
  RTOSCTL_LOG="$TMP_DIR/${RTOSCTL_LOG_NAME}.log"
fi

if [[ "$SCRIPT_LOG_NAME" == *.log ]]; then
  SCRIPT_LOG="$TMP_DIR/$SCRIPT_LOG_NAME"
else
  SCRIPT_LOG="$TMP_DIR/${SCRIPT_LOG_NAME}.log"
fi

mkdir -p "$TMP_DIR"
: > "$SCRIPT_LOG"
exec > >(tee -a "$SCRIPT_LOG") 2>&1
echo "=== $(date -u +'%Y-%m-%d %H:%M:%S UTC') run_singlehost_rtosctl.sh started ==="
echo "Script log: $SCRIPT_LOG"

cleanup() {
  local exit_code=$?
  if [[ -n "${RTOSCTL_PID:-}" ]] && kill -0 "$RTOSCTL_PID" >/dev/null 2>&1; then
    if [[ "$exit_code" -ne 0 || "$INTERRUPTED" -eq 1 || "$KEEP_RTOSCTL_ON_SUCCESS" != "1" ]]; then
      echo "Cleaning up: stopping rtosctl pid $RTOSCTL_PID"
      if ! kill "$RTOSCTL_PID" >/dev/null 2>&1; then
        echo "Warning: failed to stop rtosctl pid $RTOSCTL_PID" >&2
      fi
      wait "$RTOSCTL_PID" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$exit_code" -ne 0 && -n "${RTOSCTL_PID:-}" ]]; then
    echo "Hint: if rtosctl is still running, stop it manually: kill $RTOSCTL_PID" >&2
  fi
  return "$exit_code"
}

on_signal() {
  INTERRUPTED=1
  exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd python3
require_cmd cargo
require_cmd bun
require_cmd jq
require_cmd curl

#if [[ ! -f "$VAULT_FILE" ]]; then
#  echo "Vault file not found: $VAULT_FILE" >&2
#  exit 1
#fi

detect_master_key() {
  if [[ -n "${VAULT_MASTER_KEY:-}" ]]; then
    echo "$VAULT_MASTER_KEY"
    return 0
  fi
  if [[ -f "$RUN_NET_DIR/rtosctl_blank.json" ]]; then
    local blank_key
    blank_key="$(jq -r '.vault.url // empty' "$RUN_NET_DIR/rtosctl_blank.json" | sed -n 's/.*master_key=\([0-9a-fA-F]\+\).*/\1/p' | head -n1)"
    if [[ -n "$blank_key" ]]; then
      echo "$blank_key"
      return 0
    fi
  fi
  return 1
}

if [[ -z "${VAULT_URL:-}" ]]; then
  MASTER_KEY="$(detect_master_key || true)"
  if [[ -z "${MASTER_KEY:-}" ]]; then
    echo "Set VAULT_MASTER_KEY (or VAULT_URL) before run." >&2
    exit 1
  fi
  export VAULT_URL="file://$VAULT_FILE&master_key=$MASTER_KEY"
fi

echo "[1/8] Starting singlehost network (--elections)..."
cd "$RUN_NET_DIR"
RUN_NET_ARGS=(--elections)
if [[ "$NOBUILD" == "1" || "$NOBUILD" == "true" || "$NOBUILD" == "yes" ]]; then
  RUN_NET_ARGS+=(--nobuild)
fi
PYTHONUNBUFFERED=1 python3 -u test_run_net.py "${RUN_NET_ARGS[@]}"

if [[ ! -f "$RTOSCTL_CONFIG" ]]; then
  echo "Generated config not found: $RTOSCTL_CONFIG" >&2
  exit 1
fi

echo "[2/8] Enabling all bindings in rtosctl config..."
python3 - "$RTOSCTL_CONFIG" <<'PY'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
for b in cfg.get("bindings", {}).values():
    b["enable"] = True
json.dump(cfg, open(p, "w"), indent=2)
PY

rpc_seqno() {
  curl -sS -X POST 'http://127.0.0.1:3301/jsonRPC' \
    -H 'Content-Type: application/json' \
    -d '{"id":"1","jsonrpc":"2.0","method":"getMasterchainInfo","params":{}}' \
    | jq -r '.result.last.seqno // empty'
}

echo "[3/8] Waiting for blockchain progress (seqno increments)..."
seq_a=""
for _ in $(seq 1 60); do
  seq_a="$(rpc_seqno || true)"
  [[ "$seq_a" =~ ^[0-9]+$ ]] && break
  sleep 2
done
if [[ ! "$seq_a" =~ ^[0-9]+$ ]]; then
  echo "Failed to read masterchain seqno from 127.0.0.1:3301" >&2
  exit 1
fi
sleep 8
seq_b="$(rpc_seqno || true)"
if [[ ! "$seq_b" =~ ^[0-9]+$ ]] || (( seq_b <= seq_a )); then
  echo "Masterchain seqno is not growing (seqno: $seq_a -> ${seq_b:-n/a})" >&2
  exit 1
fi
echo "  seqno: $seq_a -> $seq_b"

echo "[4/8] Starting rtosctl service in background..."
cd "$REPO_ROOT"
: > "$RTOSCTL_LOG"
cargo run -p rtosctl -- service --config "$RTOSCTL_CONFIG" > "$RTOSCTL_LOG" 2>&1 &
RTOSCTL_PID=$!
sleep 2
if ! kill -0 "$RTOSCTL_PID" >/dev/null 2>&1; then
  echo "rtosctl failed to start; log tail:" >&2
  tail -n 120 "$RTOSCTL_LOG" >&2 || true
  exit 1
fi

wait_log_pattern() {
  local pattern="$1"
  local timeout="$2"
  local waited=0
  while (( waited < timeout )); do
    if grep -q "$pattern" "$RTOSCTL_LOG"; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

wait_log_pattern "master wallet opened: address=" 90 || {
  echo "No 'master wallet opened' in rtosctl log." >&2
  tail -n 120 "$RTOSCTL_LOG" >&2 || true
  exit 1
}

MASTER_ADDR="$(grep -m1 -oE 'master wallet opened: address=[^ ]+' "$RTOSCTL_LOG" | sed 's/.*address=//')"
if [[ -z "$MASTER_ADDR" ]]; then
  echo "Failed to detect master wallet address from rtosctl log." >&2
  exit 1
fi
echo "  master wallet: $MASTER_ADDR"

echo "[5/8] Installing bun deps (if needed)..."
cd "$LOAD_NET_DIR"
if [[ ! -d node_modules ]]; then
  bun install
fi

echo "[6/8] Top-up master/wallets/pools..."
bun run topup "$MASTER_ADDR" "$MASTER_TOPUP_TOS"

mapfile -t WALLET_ADDRS < <(grep -oE 'opened wallet: address=[^ ]+' "$RTOSCTL_LOG" | sed 's/.*address=//' | sort -u)
mapfile -t POOL_ADDRS < <(grep -oE 'opened nominator pool: address=[^ ]+' "$RTOSCTL_LOG" | sed 's/.*address=//' | sort -u)

for a in "${WALLET_ADDRS[@]}"; do
  bun run topup "$a" "$WALLET_TOPUP_TOS"
done
for a in "${POOL_ADDRS[@]}"; do
  bun run topup "$a" "$POOL_TOPUP_TOS"
done

participant_count() {
  curl -sS -X POST 'http://127.0.0.1:3301/jsonRPC' \
    -H 'Content-Type: application/json' \
    -d '{"id":"1","jsonrpc":"2.0","method":"runGetMethod","params":{"address":"-1:3333333333333333333333333333333333333333333333333333333333333333","method":"participant_list_extended","stack":[]}}' \
    | jq -r '.result.stack[4][1].elements | length // 0'
}

echo "[7/8] Waiting for elections participants..."
START_TS="$(date +%s)"
LAST_COUNT=0
while true; do
  if grep -q "stack parser error: stack entry is not a tuple" "$RTOSCTL_LOG"; then
    echo "Tuple parser error detected in rtosctl log." >&2
    exit 1
  fi
  cnt="$(participant_count || echo 0)"
  [[ "$cnt" =~ ^[0-9]+$ ]] || cnt=0
  LAST_COUNT="$cnt"
  if (( cnt > 0 )); then
    break
  fi
  now="$(date +%s)"
  if (( now - START_TS > PARTICIPANTS_WAIT_SECONDS )); then
    break
  fi
  sleep 5
done

echo "[8/8] Summary"
echo "  rtosctl pid: $RTOSCTL_PID"
echo "  rtosctl log: $RTOSCTL_LOG"
echo "  master wallet: $MASTER_ADDR"
echo "  opened wallets: ${#WALLET_ADDRS[@]}"
echo "  opened pools: ${#POOL_ADDRS[@]}"
echo "  participant_list_extended count: $LAST_COUNT"
if grep -q "stack parser error: stack entry is not a tuple" "$RTOSCTL_LOG"; then
  echo "  parser status: FAILED"
  exit 1
fi
echo "  parser status: OK (no tuple parser errors found)"
echo
echo "Service is running in background."
echo "Stop command: kill $RTOSCTL_PID"
