#!/usr/bin/env bash
# run_ciphertext_robustness.sh — Ciphertext robustness backend
#
# Parameters are supplied by testScripts/implementation_checks/ciphertext_robustness/run.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CHECK_DIR="$ROOT_DIR/testScripts/implementation_checks/ciphertext_robustness"

# ---- Required parameters (fail-fast) ----
MODE="${MODE:?MODE is required}"
RESULT_DIR="${RESULT_DIR:?RESULT_DIR is required}"
WORK_DIR="${WORK_DIR:?WORK_DIR is required}"

# ---- Protocol parameters ----
SAME_LEN_TESTS="${SAME_LEN_TESTS:-50}"
DIFF_LEN_TESTS="${DIFF_LEN_TESTS:-50}"
TEST_PORT="${TEST_PORT:-42570}"
TEST_USER="${TEST_USER:-$(id -un)}"
TEST_HOST="${TEST_HOST:-127.0.0.1}"

# ---- Local decaps parameters ----
DECAPS_WARMUP="${DECAPS_WARMUP:-100}"
DECAPS_ITERATIONS="${DECAPS_ITERATIONS:-500}"
DECAPS_CORE="${DECAPS_CORE:-0}"

# ---- Binaries ----
SSH_BIN="${SSH_BIN:-$ROOT_DIR/ssh}"
SSHD_BIN="${SSHD_BIN:-$ROOT_DIR/sshd}"
SSH_KEYGEN_BIN="${SSH_KEYGEN_BIN:-$ROOT_DIR/ssh-keygen}"
SSHD_SESSION_BIN="${SSHD_SESSION_BIN:-$ROOT_DIR/sshd-session}"
SSHD_AUTH_BIN="${SSHD_AUTH_BIN:-$ROOT_DIR/sshd-auth}"

SUDO_BIN="${SUDO_BIN:-sudo}"

# ---- Helpers ----
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing: $1"; exit 1; }; }
us_ts() { date '+%Y-%m-%dT%H:%M:%S%z'; }
log_info() { printf '[%s][INFO] %s\n' "$(us_ts)" "$*"; }

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then "$@"; return; fi
  "$SUDO_BIN" "$@"
}

# ================================================================
# ================================================================
# Local decapsulation microbenchmark
# ================================================================
run_local_decaps() {
  log_info "Local decaps starting (warmup=$DECAPS_WARMUP, iterations=$DECAPS_ITERATIONS)"

  mkdir -p "$RESULT_DIR"

  local microbench_src="$CHECK_DIR/microbench_decaps.c"
  local microbench_bin="$WORK_DIR/microbench_decaps"

    # ---- Compile against a real liboqs implementation ----
    local cflags="" libs=""

    if [[ -f "$ROOT_DIR/oqs/include/oqs/oqs.h" &&
          -e "$ROOT_DIR/oqs-test/tmp/lib/liboqs.so" ]]; then
      cflags="-I$ROOT_DIR/oqs/include -DUSE_LIBOQS"
      libs="-L$ROOT_DIR/oqs-test/tmp/lib -Wl,-rpath,$ROOT_DIR/oqs-test/tmp/lib -loqs -lcrypto"
      log_info "using repository-local liboqs"
    elif pkg-config --exists liboqs 2>/dev/null; then
      cflags="$(pkg-config --cflags liboqs) -DUSE_LIBOQS"
      libs="$(pkg-config --libs liboqs)"
      log_info "liboqs found via pkg-config"
    elif [[ -f "/usr/local/include/oqs/oqs.h" &&
            -e "/usr/local/lib/liboqs.so" ]]; then
      cflags="-I/usr/local/include -DUSE_LIBOQS"
      libs="-L/usr/local/lib -Wl,-rpath,/usr/local/lib -loqs -lcrypto"
      log_info "liboqs found under /usr/local"
    else
      echo "[ERR] a real liboqs installation is required for the decapsulation benchmark"
      echo "[HINT] build the repository-local liboqs first"
      exit 1
    fi

  # shellcheck disable=SC2086
  gcc -O2 -o "$microbench_bin" "$microbench_src" $cflags $libs -lm 2>&1 || {
    echo "[ERR] compilation failed"
    exit 1
  }

  # ---- Run ----
  if command -v taskset >/dev/null 2>&1; then
    log_info "pinning to CPU $DECAPS_CORE"
    taskset -c "$DECAPS_CORE" "$microbench_bin" "$DECAPS_WARMUP" "$DECAPS_ITERATIONS" | tee "$RESULT_DIR/local_decaps_report.md"
  else
    "$microbench_bin" "$DECAPS_WARMUP" "$DECAPS_ITERATIONS" | tee "$RESULT_DIR/local_decaps_report.md"
  fi

  log_info "Local decaps done"
}

# ================================================================
# Build mutation-enabled sshd
# ================================================================
build_mutation_sshd() {
  log_info "Building mutation-enabled sshd..."

  if ! grep -q "KEM_TEST_MUTATION" "$ROOT_DIR/auth2-kem.c"; then
    echo "[ERR] KEM_TEST_MUTATION instrumentation is not present in auth2-kem.c"
    exit 1
  fi

  local orig_cflags
  orig_cflags="$(grep '^CFLAGS=' "$ROOT_DIR/Makefile" | head -1 | sed 's/^CFLAGS=//')"

  (
    cd "$ROOT_DIR"

    # CFLAGS changes alone do not invalidate existing object files.
    # Force auth2-kem.c and the affected server binaries to be rebuilt.
    rm -f auth2-kem.o sshd sshd-session sshd-auth

    make CFLAGS="-DKEM_TEST_MUTATION $orig_cflags" \
      -j4 sshd sshd-session sshd-auth
  )

  log_info "Mutation-enabled server binaries built"
}

restore_normal_sshd() {
  log_info "Restoring normal server binaries..."

  (
    cd "$ROOT_DIR"

    rm -f auth2-kem.o sshd sshd-session sshd-auth

    make -j4 sshd sshd-session sshd-auth
  )

  log_info "Normal server binaries restored"
}

# ================================================================
# Main dispatch
# ================================================================
mkdir -p "$RESULT_DIR" "$WORK_DIR"

case "$MODE" in
  protocol)
    # ---- Source the shared SSH test harness ----
    HOST_KEY_ALGS="${HOST_KEY_ALGS:-ssh-mldsa-65}"
    MAX_STARTUPS="${MAX_STARTUPS:-1024}"
    MAX_SESSIONS="${MAX_SESSIONS:-1}"
    LOG_LEVEL="${LOG_LEVEL:-DEBUG1}"
    source "$ROOT_DIR/testScripts/backends/sshd_test_harness.sh"
    check_ssh_binaries || exit 1

    # ---- Cleanup ----
    run_root pkill -f "sshd.*-f.*${WORK_DIR}" 2>/dev/null || true
    sleep 1
    rm -f "$WORK_DIR/ssh_host_mldsa65_key" "$WORK_DIR/ssh_host_mldsa65_key.pub"
    rm -f "$WORK_DIR/id_ed25519" "$WORK_DIR/id_ed25519.pub"
    mkdir -p "$WORK_DIR" "$RESULT_DIR"

    # ---- Generate keys ----
    HOST_KEY_ALGS="ssh-mldsa-65"
    HOST_KEY_MD65="$(gen_host_key_mldsa65 "$WORK_DIR")"
    KNOWN_HOSTS="$WORK_DIR/known_hosts"
    gen_known_hosts "$WORK_DIR" "$HOST_KEY_MD65.pub" >/dev/null

    # ---- Generate KEM identity if needed ----
    KEM_ID_FILE="$WORK_DIR/id_mlkem768"
    if [[ ! -f "$KEM_ID_FILE" ]]; then
      bash "$ROOT_DIR/testScripts/backends/generate_kem_identity.sh" "$KEM_ID_FILE" "ML-KEM-768" 2>/dev/null || {
        echo "[ERR] Cannot generate KEM identity"
        exit 1
      }
    fi

    KEM_PUBLIC_B64="$(awk 'BEGIN{IGNORECASE=1} $1~/^public$/{print $2; exit}' "$KEM_ID_FILE")"
    AUTHORIZED_KEM_KEYS="$WORK_DIR/authorized_kem_keys"
    printf 'ML-KEM-768 %s\n' "$KEM_PUBLIC_B64" > "$AUTHORIZED_KEM_KEYS"

    SSHD_CFG="$WORK_DIR/sshd.conf"
    write_sshd_config_kem_only "$SSHD_CFG" "$HOST_KEY_MD65" "$AUTHORIZED_KEM_KEYS"

    ID_ED25519="$(gen_user_key_ed25519 "$WORK_DIR")"
    KEM_CLIENT_OPTS="$(build_client_opts "$KNOWN_HOSTS" "$ID_ED25519" "$KEM_ID_FILE" "yes" "ML-KEM-768")"

    RAW_CSV="$RESULT_DIR/protocol_raw.csv"
    SUMMARY_CSV="$RESULT_DIR/protocol_summary.csv"
    :> "$RAW_CSV"
    echo "mutation_type,test_id,server_challenge_epoch,server_response_epoch,remote_latency_ms,response_type,response_len,client_retcode,auth_result,error_info" > "$RAW_CSV"

    # ---- Protocol test runner ----
    run_single_test() {
      local mut_type="$1" test_id="$2"
      export KEM_MUTATION_TYPE="$mut_type"

      local log_file="$WORK_DIR/log_${mut_type}_${test_id}.log"
      rm -f "$log_file"

      local sshd_pid
      "$SSHD_BIN" -D -E "$log_file" -f "$SSHD_CFG" 2>/dev/null &
      sshd_pid=$!
      sleep 1

      if ! kill -0 "$sshd_pid" 2>/dev/null; then
        echo "${mut_type},${test_id},NA,NA,NA,NO_RESPONSE,0,-1,sshd_died,sshd_start_failed" >> "$RAW_CSV"
        rm -f "$log_file"
        return 0
      fi

      local retcode=0 client_output
      # shellcheck disable=SC2086
      client_output="$("$SSH_BIN" $KEM_CLIENT_OPTS "$TEST_USER@$TEST_HOST" true </dev/null 2>&1)" || retcode=$?

      local challenge_epoch="NA" response_epoch="NA"
      challenge_epoch="$(grep 'KEM_CHALLENGE_EPOCH:' "$log_file" 2>/dev/null | head -1 | sed 's/.*KEM_CHALLENGE_EPOCH://' | sed 's/ \[preauth\].*//' || echo "NA")"
      response_epoch="$(grep 'KEM_RESPONSE_EPOCH:' "$log_file" 2>/dev/null | head -1 | sed 's/.*KEM_RESPONSE_EPOCH://' | sed 's/ \[preauth\].*//' || echo "NA")"

      local remote_latency_ms="NA"
      if [[ "$challenge_epoch" != "NA" && "$response_epoch" != "NA" ]]; then
        remote_latency_ms="$(python3 -c "
cs = '$challenge_epoch'
rs = '$response_epoch'
cparts = cs.replace('.', ' ').split()
rparts = rs.replace('.', ' ').split()
if len(cparts) == 2 and len(rparts) == 2:
    ct = float(cparts[0]) + float(cparts[1]) / 1e9
    rt = float(rparts[0]) + float(rparts[1]) / 1e9
    print(f'{(rt - ct) * 1000:.3f}')
else:
    print('NA')
" 2>/dev/null || echo "NA")"
      fi

      local response_type="unknown" response_len="0" auth_result="unknown" error_info="none"
      [[ "$response_epoch" != "NA" ]] && response_type="KEM_RESPONSE"

      if [[ "$retcode" -eq 0 ]]; then
        auth_result="success"
      elif echo "$client_output" | grep -qi "permission denied\|authentication"; then
        auth_result="auth_failed"
      elif echo "$client_output" | grep -qi "connection reset\|connection refused\|broken pipe"; then
        auth_result="connection_error"
        error_info="connection_reset"
      elif echo "$client_output" | grep -qi "timeout\|timed out"; then
        auth_result="timeout"
        error_info="timeout"
      else
        auth_result="other_failure"
        error_info="retcode_${retcode}"
      fi

      local crash=0
      if ! kill -0 "$sshd_pid" 2>/dev/null; then
        crash=1
        error_info="${error_info};sshd_crashed"
      fi

      echo "${mut_type},${test_id},${challenge_epoch},${response_epoch},${remote_latency_ms},${response_type},${response_len},${retcode},${auth_result},${error_info}" >> "$RAW_CSV"

      if [[ "$crash" -eq 0 ]]; then
        kill "$sshd_pid" 2>/dev/null || true
        wait "$sshd_pid" 2>/dev/null || true
      fi
      rm -f "$log_file"
      sleep 0.5
    }

    # ---- Run tests ----
    SAME_LEN_TYPES="valid onebit multibit random allzero allff"
    DIFF_LEN_TYPES="truncated extended"

    SAME_LEN_TESTLIST="$WORK_DIR/same_len_testlist.txt"
    :> "$SAME_LEN_TESTLIST"
    for mut in $SAME_LEN_TYPES; do
      for ((i=0; i<SAME_LEN_TESTS; i++)); do echo "$mut $i" >> "$SAME_LEN_TESTLIST"; done
    done
    shuf "$SAME_LEN_TESTLIST" > "$WORK_DIR/same_len_shuffled.txt"
    mv "$WORK_DIR/same_len_shuffled.txt" "$SAME_LEN_TESTLIST"

    DIFF_LEN_TESTLIST="$WORK_DIR/diff_len_testlist.txt"
    :> "$DIFF_LEN_TESTLIST"
    for mut in $DIFF_LEN_TYPES; do
      for ((i=0; i<DIFF_LEN_TESTS; i++)); do echo "$mut $i" >> "$DIFF_LEN_TESTLIST"; done
    done
    shuf "$DIFF_LEN_TESTLIST" > "$WORK_DIR/diff_len_shuffled.txt"
    mv "$WORK_DIR/diff_len_shuffled.txt" "$DIFF_LEN_TESTLIST"

    total_same=$(( $(echo "$SAME_LEN_TYPES" | wc -w) * SAME_LEN_TESTS ))
    log_info "Running $total_same same-length tests..."
    same_count=0
    while IFS=' ' read -r mut test_id; do
      [[ -z "$mut" ]] && continue
      run_single_test "$mut" "$test_id" || true
      same_count=$((same_count + 1))
      (( same_count % 20 == 0 )) && log_info "same-length: $same_count/$total_same"
    done < "$SAME_LEN_TESTLIST"

    total_diff=$(( $(echo "$DIFF_LEN_TYPES" | wc -w) * DIFF_LEN_TESTS ))
    log_info "Running $total_diff diff-length tests..."
    diff_count=0
    while IFS=' ' read -r mut test_id; do
      [[ -z "$mut" ]] && continue
      run_single_test "$mut" "$test_id" || true
      diff_count=$((diff_count + 1))
      (( diff_count % 20 == 0 )) && log_info "diff-length: $diff_count/$total_diff"
    done < "$DIFF_LEN_TESTLIST"

    log_info "Protocol test done ($same_count same + $diff_count diff)"

    # ---- Analyze ----
    if [[ -f "$CHECK_DIR/analyze.py" ]]; then
    if ! python3 "$CHECK_DIR/analyze.py" \
      protocol \
      "$RAW_CSV" \
      "$SUMMARY_CSV" \
      "$RESULT_DIR/protocol_report.md"; then
      echo "[ERR] protocol result analysis failed"
      exit 1
    fi
  fi
    ;;
  local)
    run_local_decaps
    ;;
  build)
    build_mutation_sshd
    ;;
  restore)
    restore_normal_sshd
    ;;
  *)
    echo "[ERR] unknown mode: $MODE (expected: protocol|local|build|restore)"
    exit 1
    ;;
esac

log_info "Done. Results in $RESULT_DIR"
