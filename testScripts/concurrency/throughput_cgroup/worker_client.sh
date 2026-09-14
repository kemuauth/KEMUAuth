#!/usr/bin/env bash
# worker_client.sh — single concurrency worker: loop SSH connections and record results
#
# Usage:
#   bash worker_client.sh <ssh_bin> <user> <host> <port> \
#       <duration_sec> <client_opts> <result_csv> <cpuset> <worker_id> [barrier_dir]
#
# Behavior:
#   - If barrier_dir is provided, create ready_<id> signal file, wait for go file
#   - Loop: ssh ... true → record latency → next round immediately
#   - Stop when barrier_dir/stop appears or duration_sec is exceeded
#   - Bind self to cpuset (if specified)

set -euo pipefail

SSH_BIN="$1"
TEST_USER="$2"
TEST_HOST="$3"
TEST_PORT="$4"
DURATION_SEC="$5"
CLIENT_OPTS="$6"
RESULT_CSV="$7"
CPUSET="${8:-}"
WORKER_ID="${9:-0}"
BARRIER_DIR="${10:-}"

# ---- Bind CPU ----
if [[ -n "$CPUSET" ]]; then
  taskset -cp "$CPUSET" $$ >/dev/null 2>&1 || true
fi

# ---- Barrier synchronization ----
if [[ -n "$BARRIER_DIR" && -d "$BARRIER_DIR" ]]; then
  # Signal ready
  touch "$BARRIER_DIR/ready_${WORKER_ID}"

  # Wait for go signal
  barrier_waited=0
  while [[ ! -f "$BARRIER_DIR/go" ]]; do
    sleep 0.05
    barrier_waited=$((barrier_waited + 1))
    if [[ $barrier_waited -gt 100 ]]; then
      echo "[WARN] worker $WORKER_ID: barrier timeout" >&2
      exit 1
    fi
  done
fi

# Read barrier release time
BARRIER_GO_EPOCH=""
if [[ -f "$BARRIER_DIR/go" ]]; then
  BARRIER_GO_EPOCH="$(cat "$BARRIER_DIR/go")"
fi

# ---- Main loop ----
read -ra SSH_OPTS <<< "$CLIENT_OPTS"

echo "[worker $WORKER_ID] opts count=${#SSH_OPTS[@]}" >> /tmp/worker_debug.log
echo "[worker $WORKER_ID] opts: ${SSH_OPTS[*]}" >> /tmp/worker_debug.log

start_time="$(date +%s)"
conn_id=0

while true; do
  # Check timeout
  current_time="$(date +%s)"
  elapsed=$((current_time - start_time))
  if [[ $elapsed -ge $DURATION_SEC ]]; then
    break
  fi

  # Check stop signal
  if [[ -n "$BARRIER_DIR" && -f "$BARRIER_DIR/stop" ]]; then
    break
  fi

  # Record start time
  conn_start_epoch="$(date +%s.%N)"

  # Execute SSH connection (keep stderr for debugging first few connections)
  retcode=0
  error_class="none"

  ssh_stderr="$(mktemp /tmp/ssh_worker_XXXXXX)"
  # shellcheck disable=SC2086
  "$SSH_BIN" \
    "${SSH_OPTS[@]}" \
    "$TEST_USER@$TEST_HOST" \
    true >/dev/null 2>"$ssh_stderr" || retcode=$?

  # Debug: keep stderr for first 3 failures
  if [[ "$retcode" -ne 0 && "$conn_id" -lt 3 ]]; then
    cp "$ssh_stderr" "/tmp/ssh_worker_err_${WORKER_ID}_${conn_id}.txt"
  fi
  rm -f "$ssh_stderr"

  # Record end time
  conn_end_epoch="$(date +%s.%N)"

  # Calculate latency (milliseconds)
  latency_ms="$(python3 -c "
s = float('$conn_start_epoch')
e = float('$conn_end_epoch')
print(f'{(e - s) * 1000:.2f}')
" 2>/dev/null || echo "NA")"

  # Classify error
  success=0
  if [[ "$retcode" -eq 0 ]]; then
    success=1
  elif [[ "$retcode" -eq 255 ]]; then
    error_class="connection_error"
  elif [[ "$retcode" -eq 124 ]]; then
    error_class="timeout"
  else
    error_class="other_retcode_${retcode}"
  fi

  # Write result
  echo "${WORKER_ID}_${conn_id},${conn_start_epoch},${conn_end_epoch},${latency_ms},${success},${retcode},${error_class}" >> "$RESULT_CSV"

  conn_id=$((conn_id + 1))
done

exit 0
