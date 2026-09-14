#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

RTT_MS="${RTT_MS:-}"
INITCWND_LIST="${INITCWND_LIST:-}"
ITERATIONS="${ITERATIONS:-}"
WARMUP="${WARMUP:-}"
ROUNDS="${ROUNDS:-}"
ROTATE_CASE_ORDER="${ROTATE_CASE_ORDER:-1}"
FORCE_DISABLE_OFFLOAD="${FORCE_DISABLE_OFFLOAD:-1}"
NETWORK_MODE="${NETWORK_MODE:-loopback}"
TEST_USER="${TEST_USER:-$(id -un)}"
TEST_HOST="${TEST_HOST:-127.0.0.1}"
BASE_PORT="${BASE_PORT:-42460}"
NETEM_IFACE="${NETEM_IFACE:-}"
RESULT_DIR="${RESULT_DIR:-$ROOT_DIR/testScripts/figure5/results/test3}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/testScripts/.work-test3}"
SUDO_BIN="${SUDO_BIN:-sudo}"
SUDO_NONINTERACTIVE="${SUDO_NONINTERACTIVE:-0}"

SSH_BIN="${SSH_BIN:-$ROOT_DIR/ssh}"
SSHD_BIN="${SSHD_BIN:-$ROOT_DIR/sshd}"
SSH_KEYGEN_BIN="${SSH_KEYGEN_BIN:-$ROOT_DIR/ssh-keygen}"
SSHD_SESSION_BIN="${SSHD_SESSION_BIN:-$ROOT_DIR/sshd-session}"
SSHD_AUTH_BIN="${SSHD_AUTH_BIN:-$ROOT_DIR/sshd-auth}"

ID_ED25519_FILE="${ID_ED25519_FILE:-$WORK_DIR/id_ed25519}"
ID_MD65_FILE="${ID_MD65_FILE:-$WORK_DIR/id_mldsa65}"
ID_SD192F_FILE="${ID_SD192F_FILE:-$WORK_DIR/id_slhdsa192f}"
ID_MK768_FILE="${ID_MK768_FILE:-$ROOT_DIR/testScripts/.work-kem/id_mlkem768}"

HOSTKEY_ED25519_FILE="${HOSTKEY_ED25519_FILE:-$WORK_DIR/ssh_host_ed25519_key}"
HOSTKEY_MD65_FILE="${HOSTKEY_MD65_FILE:-$WORK_DIR/ssh_host_mldsa65_key}"
HOSTKEY_SD192F_FILE="${HOSTKEY_SD192F_FILE:-$WORK_DIR/ssh_host_slhdsa192f_key}"

RAW_CSV="$RESULT_DIR/raw_runs.csv"
TABLE_CSV="$RESULT_DIR/test3_values.csv"
ROUND_TABLE_CSV="$RESULT_DIR/test3_round_values.csv"
WINDOW_Q_CSV="$RESULT_DIR/window_p5_p50_p95.csv"
META_TXT="$RESULT_DIR/metadata.txt"
KNOWN_HOSTS="$WORK_DIR/known_hosts"
AUTHORIZED_KEYS="$WORK_DIR/authorized_keys"
AUTHORIZED_KEM_KEYS="$WORK_DIR/authorized_kem_keys"
SSHD_LOG="$WORK_DIR/sshd.log"

SSHD_PID=""
ORIG_LOCAL_ROUTE=""
LOCAL_ROUTE_TOUCHED=0
ORIG_IFACE_MTU=""
IFACE_MTU_TOUCHED=0
OFFLOAD_TOUCHED=0
ORIG_LO_TSO=""
ORIG_LO_GSO=""
ORIG_LO_GRO=""
NETEM_TOUCHED=0
NS_TOUCHED=0
SUDO_READY=0
SERVER_NS="t3s$$"
CLIENT_NS="t3c$$"
VETH_SERVER="v6s$$"
VETH_CLIENT="v6c$$"
SERVER_IP="10.66.6.1"
CLIENT_IP="10.66.6.2"

usage() {
  cat <<'EOF'
Usage:
  run_test3.sh [options]

Options:
  -r, --rounds <n>            Number of rounds per initcwnd (required; or env ROUNDS)
  -i, --iterations <n>        Measure iterations per round (required; or env ITERATIONS)
  -w, --warmup <n>            Warmup iterations per round (required; or env WARMUP)
      --initcwnd-list "..."   Space-separated initcwnd list (required; or env INITCWND_LIST)
      --rotate <0|1>          Rotate case order between rounds (default: 1)
      --rtt <ms>              Target RTT in milliseconds (required; or env RTT_MS)
      --iface <name>          Netem interface (required; or env NETEM_IFACE)
      --mode <loopback|netns> Network path mode (default: loopback)
      --offload-fix <0|1>     On lo, disable tso/gso/gro during test (default: 1)
  -h, --help                  Show this help

Example:
  bash testScripts/backends/run_test3.sh --rounds 5 --iterations 5 --warmup 1
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -r|--rounds)
        ROUNDS="$2"
        shift 2
        ;;
      -i|--iterations)
        ITERATIONS="$2"
        shift 2
        ;;
      -w|--warmup)
        WARMUP="$2"
        shift 2
        ;;
      --initcwnd-list)
        INITCWND_LIST="$2"
        shift 2
        ;;
      --rotate)
        ROTATE_CASE_ORDER="$2"
        shift 2
        ;;
      --rtt)
        RTT_MS="$2"
        shift 2
        ;;
      --iface)
        NETEM_IFACE="$2"
        shift 2
        ;;
      --mode)
        NETWORK_MODE="$2"
        shift 2
        ;;
      --offload-fix)
        FORCE_DISABLE_OFFLOAD="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "[ERR] unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERR] missing command: $1"; exit 1; }
}

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return
  fi
  if ! command -v "$SUDO_BIN" >/dev/null 2>&1; then
    echo "[ERR] sudo not found and current user is not root"
    exit 1
  fi
  if [[ "$SUDO_NONINTERACTIVE" == "1" ]]; then
    "$SUDO_BIN" -n "$@"
  else
    if [[ "$SUDO_READY" != "1" ]]; then
      "$SUDO_BIN" -v
      # sudo prompt usually has no trailing newline; force one to keep logs aligned.
      printf '\n' >&2
      SUDO_READY=1
    fi
    "$SUDO_BIN" -n "$@"
  fi
}

us_ts() {
  TZ=America/New_York date +%Y-%m-%dT%H:%M:%S%z
}

log_info() {
  printf '[%s][INFO] %s\n' "$(us_ts)" "$*"
}

cleanup() {
  if [[ -n "$SSHD_PID" ]] && kill -0 "$SSHD_PID" 2>/dev/null; then
    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi
  if [[ "$NETEM_TOUCHED" == "1" ]]; then
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      run_root ip netns exec "$CLIENT_NS" tc qdisc del dev "$VETH_CLIENT" root >/dev/null 2>&1 || true
      run_root ip netns exec "$SERVER_NS" tc qdisc del dev "$VETH_SERVER" root >/dev/null 2>&1 || true
    else
      run_root tc qdisc del dev "$NETEM_IFACE" root >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$IFACE_MTU_TOUCHED" == "1" && -n "$ORIG_IFACE_MTU" ]]; then
    run_root ip link set dev "$NETEM_IFACE" mtu "$ORIG_IFACE_MTU" >/dev/null 2>&1 || true
  fi
  if [[ "$OFFLOAD_TOUCHED" == "1" && "$NETEM_IFACE" == "lo" ]]; then
    run_root ethtool -K "$NETEM_IFACE" tso "$ORIG_LO_TSO" gso "$ORIG_LO_GSO" gro "$ORIG_LO_GRO" >/dev/null 2>&1 || true
  fi
  if [[ "$LOCAL_ROUTE_TOUCHED" == "1" && -n "$ORIG_LOCAL_ROUTE" ]]; then
    run_root ip route replace table local $ORIG_LOCAL_ROUTE >/dev/null 2>&1 || true
  fi
  if [[ "$NS_TOUCHED" == "1" ]]; then
    run_root ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
    run_root ip netns del "$SERVER_NS" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

supports_ssh_key_alg() {
  local alg="$1"
  "$SSH_BIN" -Q key 2>/dev/null | grep -Fxq "$alg"
}

ensure_pubkey_identity() {
  local alg="$1"
  local path="$2"

  if [[ -f "$path" && -f "$path.pub" ]]; then
    return 0
  fi
  if ! supports_ssh_key_alg "$alg"; then
    return 1
  fi
  mkdir -p "$(dirname "$path")"
  "$SSH_KEYGEN_BIN" -q -t "$alg" -N "" -f "$path" >/dev/null
}

ensure_kem_identity() {
  local path="$1"
  if [[ -f "$path" ]]; then
    return 0
  fi
  mkdir -p "$(dirname "$path")"
  bash "$ROOT_DIR/testScripts/backends/generate_kem_identity.sh" "$path" "ML-KEM-768" >/dev/null
}

extract_kem_public() {
  local f="$1"
  awk 'BEGIN{IGNORECASE=1} $1 ~ /^public$/ {print $2; exit}' "$f"
}

prepare_authorized_files() {
  : > "$AUTHORIZED_KEYS"
  : > "$AUTHORIZED_KEM_KEYS"

  for key in "$ID_ED25519_FILE" "$ID_MD65_FILE" "$ID_SD192F_FILE"; do
    if [[ -f "$key.pub" ]]; then
      cat "$key.pub" >> "$AUTHORIZED_KEYS"
    fi
  done

  if [[ -f "$ID_MK768_FILE" ]]; then
    local pub
    pub="$(extract_kem_public "$ID_MK768_FILE" || true)"
    if [[ -n "$pub" ]]; then
      printf 'ML-KEM-768 %s\n' "$pub" >> "$AUTHORIZED_KEM_KEYS"
    fi
  fi
}

write_sshd_config() {
  local cfg="$1"
  local server_alg="$2"
  local port="$3"

  {
    echo "Port $port"
    echo "ListenAddress $TEST_HOST"
    echo "PidFile $WORK_DIR/sshd_${port}.pid"
    echo "LogLevel ERROR"
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
    echo "ChallengeResponseAuthentication no"
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication yes"
    echo "PubkeyAcceptedAlgorithms ssh-ed25519,ssh-mldsa-65,ssh-slhdsapuresha2192f"
    echo "KEMAuthentication yes"
    echo "KEMAuthAlgorithms ML-KEM-768"
    echo "KexAlgorithms mlkem768x25519-sha256"
    echo "AuthorizedKeysFile $AUTHORIZED_KEYS"
    echo "AuthorizedKEMKeysFile $AUTHORIZED_KEM_KEYS"
    echo "SshdSessionPath $SSHD_SESSION_BIN"
    echo "SshdAuthPath $SSHD_AUTH_BIN"
    echo "StrictModes no"

    case "$server_alg" in
      ssh-ed25519)
        echo "AuthenticationMethods publickey"
        echo "HostKey $HOSTKEY_ED25519_FILE"
        echo "HostKeyAlgorithms ssh-ed25519"
        ;;
      ssh-mldsa-65)
        echo "AuthenticationMethods publickey"
        echo "HostKey $HOSTKEY_MD65_FILE"
        echo "HostKeyAlgorithms ssh-mldsa-65"
        ;;
      ssh-slhdsapuresha2192f)
        echo "AuthenticationMethods publickey"
        echo "HostKey $HOSTKEY_SD192F_FILE"
        echo "HostKeyAlgorithms ssh-slhdsapuresha2192f"
        ;;
      ML-KEM-768/md65)
        echo "AuthenticationMethods publickey-kem"
        echo "HostKey $HOSTKEY_MD65_FILE"
        echo "HostKeyAlgorithms ssh-mldsa-65"
        ;;
      ML-KEM-768/sd192f)
        echo "AuthenticationMethods publickey-kem"
        echo "HostKey $HOSTKEY_SD192F_FILE"
        echo "HostKeyAlgorithms ssh-slhdsapuresha2192f"
        ;;
      *)
        echo "[ERR] unsupported server alg profile: $server_alg" >&2
        exit 1
        ;;
    esac
  } > "$cfg"
}

setup_network_path() {
  if [[ "$NETWORK_MODE" == "loopback" ]]; then
    return 0
  fi
  if [[ "$NETWORK_MODE" != "netns" ]]; then
    echo "[ERR] unsupported mode: $NETWORK_MODE"
    exit 1
  fi

  run_root ip netns del "$SERVER_NS" >/dev/null 2>&1 || true
  run_root ip netns del "$CLIENT_NS" >/dev/null 2>&1 || true
  run_root ip netns add "$SERVER_NS"
  run_root ip netns add "$CLIENT_NS"
  run_root ip link add "$VETH_SERVER" type veth peer name "$VETH_CLIENT"
  run_root ip link set "$VETH_SERVER" netns "$SERVER_NS"
  run_root ip link set "$VETH_CLIENT" netns "$CLIENT_NS"

  run_root ip -n "$SERVER_NS" link set lo up
  run_root ip -n "$CLIENT_NS" link set lo up
  run_root ip -n "$SERVER_NS" addr add "$SERVER_IP/24" dev "$VETH_SERVER"
  run_root ip -n "$CLIENT_NS" addr add "$CLIENT_IP/24" dev "$VETH_CLIENT"
  run_root ip -n "$SERVER_NS" link set "$VETH_SERVER" up
  run_root ip -n "$CLIENT_NS" link set "$VETH_CLIENT" up
  run_root ip -n "$CLIENT_NS" route replace "$SERVER_IP/32" dev "$VETH_CLIENT"

  TEST_HOST="$SERVER_IP"
  NETEM_IFACE="$VETH_CLIENT"
  NS_TOUCHED=1
}

start_sshd() {
  local cfg="$1"
  local port="$2"

  if [[ -n "$SSHD_PID" ]] && kill -0 "$SSHD_PID" 2>/dev/null; then
    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi

  if [[ "$NETWORK_MODE" == "netns" ]]; then
    # Guard against stale listeners from previously failed runs in the same netns.
    run_root ip netns exec "$SERVER_NS" bash -lc '
      p="$1"
      ss -ltnp 2>/dev/null \
        | awk -v p="$p" "$4 ~ (\":" p \"$\") { while (match($0, /pid=[0-9]+/)) { print substr($0, RSTART+4, RLENGTH-4); $0 = substr($0, RSTART+RLENGTH) } }" \
        | sort -u | xargs -r kill -9
    ' _ "$port" >/dev/null 2>&1 || true
  else
    # Guard against stale host listeners from previously failed runs.
    if command -v ss >/dev/null 2>&1; then
      while read -r stale_pid; do
        [[ -z "$stale_pid" ]] && continue
        stale_comm="$(ps -p "$stale_pid" -o comm= 2>/dev/null || true)"
        if [[ "$stale_comm" == "sshd" ]]; then
          kill -9 "$stale_pid" >/dev/null 2>&1 || true
        fi
      done < <(
        ss -ltnp 2>/dev/null \
          | awk -v p="$port" '$4 ~ (":" p "$") { while (match($0, /pid=[0-9]+/)) { print substr($0, RSTART+4, RLENGTH-4); $0 = substr($0, RSTART+RLENGTH) } }' \
          | sort -u
      )
    fi
  fi

  if [[ "$NETWORK_MODE" == "netns" ]]; then
    run_root ip netns exec "$SERVER_NS" "$SSHD_BIN" -f "$cfg" -E "$SSHD_LOG" -D &
  else
    "$SSHD_BIN" -f "$cfg" -E "$SSHD_LOG" -D &
  fi
  SSHD_PID=$!

  for _ in $(seq 1 200); do
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      if run_root ip netns exec "$CLIENT_NS" bash -lc "exec 3<>/dev/tcp/$TEST_HOST/$port" 2>/dev/null; then
        return 0
      fi
    else
      if { exec 3<>"/dev/tcp/$TEST_HOST/$port"; } 2>/dev/null; then
        exec 3>&- || true
        exec 3<&- || true
        return 0
      fi
    fi
    # Avoid reading stdin while polling; this prevents terminal prompt/output skew.
    sleep 0.05
  done

  echo "[ERR] sshd start timeout: $cfg"
  return 1
}

run_once() {
  local case_name="$1"
  local client_mode="$2"
  local client_alg="$3"
  local id_file="$4"
  local hostkey_pref="$5"
  local port="$6"
  local initcwnd="$7"
  local round="$8"
  local phase="$9"
  local iter="${10}"

  local rc=0 start_ns end_ns delta_ms

  start_ns="$(date +%s%N)"
  if [[ "$client_mode" == "publickey" ]]; then
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      run_root ip netns exec "$CLIENT_NS" "$SSH_BIN" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=5 \
        -o KexAlgorithms=mlkem768x25519-sha256 \
        -o HostKeyAlgorithms="$hostkey_pref" \
        -o PreferredAuthentications=publickey \
        -o PubkeyAcceptedAlgorithms="$client_alg" \
        -o IdentityFile="$id_file" \
        -o KEMAuthentication=no \
        -p "$port" \
        "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
    else
      "$SSH_BIN" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=5 \
        -o KexAlgorithms=mlkem768x25519-sha256 \
        -o HostKeyAlgorithms="$hostkey_pref" \
        -o PreferredAuthentications=publickey \
        -o PubkeyAcceptedAlgorithms="$client_alg" \
        -o IdentityFile="$id_file" \
        -o KEMAuthentication=no \
        -p "$port" \
        "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
    fi
  else
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      run_root ip netns exec "$CLIENT_NS" "$SSH_BIN" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=5 \
        -o KexAlgorithms=mlkem768x25519-sha256 \
        -o HostKeyAlgorithms="$hostkey_pref" \
        -o PreferredAuthentications=publickey-kem \
        -o PubkeyAuthentication=no \
        -o KEMAuthentication=yes \
        -o KEMAuthAlgorithms=ML-KEM-768 \
        -o IdentityKEMFile="$id_file" \
        -p "$port" \
        "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
    else
      "$SSH_BIN" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o ConnectTimeout=5 \
        -o KexAlgorithms=mlkem768x25519-sha256 \
        -o HostKeyAlgorithms="$hostkey_pref" \
        -o PreferredAuthentications=publickey-kem \
        -o PubkeyAuthentication=no \
        -o KEMAuthentication=yes \
        -o KEMAuthAlgorithms=ML-KEM-768 \
        -o IdentityKEMFile="$id_file" \
        -p "$port" \
        "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
    fi
  fi
  end_ns="$(date +%s%N)"
  delta_ms="$(awk -v ns="$((end_ns-start_ns))" 'BEGIN { printf "%.3f", ns/1000000.0 }')"
  echo "$initcwnd,$round,$case_name,$phase,$iter,$rc,$delta_ms" >> "$RAW_CSV"
}

calc_quantiles_success() {
  local initcwnd="$1"
  local case_name="$2"

  awk -F, -v cw="$initcwnd" -v c="$case_name" '
    $1==cw && $3==c && $4=="measure" && $6==0 {print $7}
  ' "$RAW_CSV" | sort -n | awk '
    {a[NR]=$1}
    END {
      n=NR
      if (n==0) { print "NA NA NA"; exit }
      p5i=int(0.05*n + 0.999999)
      p50i=int(0.50*n + 0.999999)
      p95i=int(0.95*n + 0.999999)
      if (p5i<1) p5i=1
      if (p50i<1) p50i=1
      if (p95i<1) p95i=1
      if (p5i>n) p5i=n
      if (p50i>n) p50i=n
      if (p95i>n) p95i=n
      printf "%.3f %.3f %.3f\n", a[p5i], a[p50i], a[p95i]
    }
  '
}

calc_quantiles_success_round() {
  local initcwnd="$1"
  local case_name="$2"
  local round="$3"

  awk -F, -v cw="$initcwnd" -v c="$case_name" -v r="$round" '
    $1==cw && $2==r && $3==c && $4=="measure" && $6==0 {print $7}
  ' "$RAW_CSV" | sort -n | awk '
    {a[NR]=$1}
    END {
      n=NR
      if (n==0) { print "NA NA NA"; exit }
      p5i=int(0.05*n + 0.999999)
      p50i=int(0.50*n + 0.999999)
      p95i=int(0.95*n + 0.999999)
      if (p5i<1) p5i=1
      if (p50i<1) p50i=1
      if (p95i<1) p95i=1
      if (p5i>n) p5i=n
      if (p50i>n) p50i=n
      if (p95i>n) p95i=n
      printf "%.3f %.3f %.3f\n", a[p5i], a[p50i], a[p95i]
    }
  '
}

apply_rtt() {
  local one_way
  one_way="$(awk -v rtt="$RTT_MS" 'BEGIN { printf "%.3f", rtt/2.0 }')"
  if [[ "$NETWORK_MODE" == "netns" ]]; then
    run_root ip netns exec "$CLIENT_NS" tc qdisc del dev "$VETH_CLIENT" root >/dev/null 2>&1 || true
    run_root ip netns exec "$SERVER_NS" tc qdisc del dev "$VETH_SERVER" root >/dev/null 2>&1 || true
    run_root ip netns exec "$CLIENT_NS" tc qdisc add dev "$VETH_CLIENT" root netem delay "${one_way}ms"
    run_root ip netns exec "$SERVER_NS" tc qdisc add dev "$VETH_SERVER" root netem delay "${one_way}ms"
  else
    run_root tc qdisc del dev "$NETEM_IFACE" root >/dev/null 2>&1 || true
    run_root tc qdisc add dev "$NETEM_IFACE" root netem delay "${one_way}ms"
  fi
  NETEM_TOUCHED=1
}

enforce_iface_mtu_1500() {
  local current_mtu

  if [[ "$NETWORK_MODE" == "netns" ]]; then
    current_mtu="$(run_root ip -n "$CLIENT_NS" -o link show "$VETH_CLIENT" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  else
    current_mtu="$(ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  fi
  if [[ -z "$current_mtu" ]]; then
    echo "[ERR] failed to query MTU for iface=$NETEM_IFACE"
    exit 1
  fi

  ORIG_IFACE_MTU="$current_mtu"
  if [[ "$current_mtu" != "1500" ]]; then
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      log_info "adjusting $CLIENT_NS/$VETH_CLIENT MTU: $current_mtu -> 1500"
      run_root ip -n "$CLIENT_NS" link set dev "$VETH_CLIENT" mtu 1500
    else
      log_info "adjusting $NETEM_IFACE MTU: $current_mtu -> 1500"
      run_root ip link set dev "$NETEM_IFACE" mtu 1500
      IFACE_MTU_TOUCHED=1
    fi
  else
    if [[ "$NETWORK_MODE" == "netns" ]]; then
      log_info "iface=$CLIENT_NS/$VETH_CLIENT MTU already 1500"
    else
      log_info "iface=$NETEM_IFACE MTU already 1500"
    fi
  fi
}

get_offload_state() {
  local feature="$1"
  ethtool -k "$NETEM_IFACE" 2>/dev/null | awk -v f="$feature" '$1 == f":" {print $2; exit}'
}

enforce_lo_offload_settings() {
  if [[ "$FORCE_DISABLE_OFFLOAD" != "1" ]]; then
    return 0
  fi
  if [[ "$NETEM_IFACE" != "lo" ]]; then
    return 0
  fi

  if ! command -v ethtool >/dev/null 2>&1; then
    echo "[ERR] ethtool is required when FORCE_DISABLE_OFFLOAD=1 on lo"
    exit 1
  fi

  ORIG_LO_TSO="$(get_offload_state tcp-segmentation-offload)"
  ORIG_LO_GSO="$(get_offload_state generic-segmentation-offload)"
  ORIG_LO_GRO="$(get_offload_state generic-receive-offload)"

  if [[ -z "$ORIG_LO_TSO" || -z "$ORIG_LO_GSO" || -z "$ORIG_LO_GRO" ]]; then
    echo "[ERR] failed to read current offload state for lo"
    exit 1
  fi

  if [[ "$ORIG_LO_TSO" != "off" || "$ORIG_LO_GSO" != "off" || "$ORIG_LO_GRO" != "off" ]]; then
    log_info "disabling lo offload: tso=$ORIG_LO_TSO gso=$ORIG_LO_GSO gro=$ORIG_LO_GRO"
    run_root ethtool -K "$NETEM_IFACE" tso off gso off gro off
    OFFLOAD_TOUCHED=1
  else
    log_info "lo offload already disabled"
  fi
}

enforce_initcwnd() {
  local cwnd="$1"

  if [[ "$NETWORK_MODE" == "netns" ]]; then
    # Match step2-step5 comparability: constrain both directions in netns mode.
    run_root ip -n "$CLIENT_NS" route replace "$SERVER_IP/32" dev "$VETH_CLIENT" initcwnd "$cwnd"
    run_root ip -n "$SERVER_NS" route replace "$CLIENT_IP/32" dev "$VETH_SERVER" initcwnd "$cwnd"
    if ! run_root ip -n "$CLIENT_NS" route show "$SERVER_IP/32" dev "$VETH_CLIENT" | grep -q "initcwnd $cwnd"; then
      echo "[ERR] initcwnd not applied in netns: $cwnd"
      exit 1
    fi
    if ! run_root ip -n "$SERVER_NS" route show "$CLIENT_IP/32" dev "$VETH_SERVER" | grep -q "initcwnd $cwnd"; then
      echo "[ERR] initcwnd not applied in netns(server): $cwnd"
      exit 1
    fi
    return 0
  fi

  if [[ "$TEST_HOST" != 127.* || "$NETEM_IFACE" != "lo" ]]; then
    echo "[ERR] initcwnd auto-enforcement currently requires TEST_HOST=127.x and NETEM_IFACE=lo"
    exit 1
  fi

  if [[ "$LOCAL_ROUTE_TOUCHED" == "0" ]]; then
    ORIG_LOCAL_ROUTE="$(ip route show table local 127.0.0.0/8 dev lo | head -n1)"
    if [[ -z "$ORIG_LOCAL_ROUTE" ]]; then
      echo "[ERR] failed to locate loopback local route"
      exit 1
    fi
    LOCAL_ROUTE_TOUCHED=1
  fi

  run_root ip route replace table local local 127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1 initcwnd "$cwnd"
  if ! ip route show table local 127.0.0.0/8 dev lo | grep -q "initcwnd $cwnd"; then
    echo "[ERR] initcwnd not applied: $cwnd"
    exit 1
  fi
}

need_cmd tc
need_cmd ip

parse_args "$@"

: "${RTT_MS:?RTT_MS is required}"
: "${INITCWND_LIST:?INITCWND_LIST is required}"
: "${ITERATIONS:?ITERATIONS is required}"
: "${WARMUP:?WARMUP is required}"
: "${ROUNDS:?ROUNDS is required}"
: "${NETEM_IFACE:?NETEM_IFACE is required}"

setup_network_path

mkdir -p "$RESULT_DIR" "$WORK_DIR"
: > "$SSHD_LOG"

if [[ ! -x "$SSH_BIN" || ! -x "$SSHD_BIN" || ! -x "$SSH_KEYGEN_BIN" || ! -x "$SSHD_SESSION_BIN" || ! -x "$SSHD_AUTH_BIN" ]]; then
  echo "[ERR] missing binaries: ssh/sshd/ssh-keygen/sshd-session/sshd-auth"
  exit 1
fi

ensure_pubkey_identity "ssh-ed25519" "$ID_ED25519_FILE"
ensure_pubkey_identity "ssh-mldsa-65" "$ID_MD65_FILE"
ensure_pubkey_identity "ssh-slhdsapuresha2192f" "$ID_SD192F_FILE"
ensure_kem_identity "$ID_MK768_FILE"

ensure_pubkey_identity "ssh-ed25519" "$HOSTKEY_ED25519_FILE"
ensure_pubkey_identity "ssh-mldsa-65" "$HOSTKEY_MD65_FILE"
ensure_pubkey_identity "ssh-slhdsapuresha2192f" "$HOSTKEY_SD192F_FILE"

prepare_authorized_files
enforce_lo_offload_settings
enforce_iface_mtu_1500
apply_rtt

echo "initcwnd,round,case,phase,iter,rc,latency_ms" > "$RAW_CSV"
echo "initcwnd_mss,A_ms,B_ms,C_ms,D_ms,E_ms" > "$TABLE_CSV"
echo "ts_us,round,initcwnd_mss,A_ms,B_ms,C_ms,D_ms,E_ms" > "$ROUND_TABLE_CSV"
echo "window,case,p5,p50,p95" > "$WINDOW_Q_CSV"

cases=(
  "A|publickey|ssh-ed25519|$ID_ED25519_FILE|ssh-ed25519|ssh-ed25519"
  "B|publickey|ssh-mldsa-65|$ID_MD65_FILE|ssh-mldsa-65|ssh-mldsa-65"
  "C|publickey|ssh-slhdsapuresha2192f|$ID_SD192F_FILE|ssh-slhdsapuresha2192f|ssh-slhdsapuresha2192f"
  "D|publickey-kem|ML-KEM-768|$ID_MK768_FILE|ssh-mldsa-65|ML-KEM-768/md65"
  "E|publickey-kem|ML-KEM-768|$ID_MK768_FILE|ssh-slhdsapuresha2192f|ML-KEM-768/sd192f"
)

case_count="${#cases[@]}"
for round in $(seq 1 "$ROUNDS"); do
  log_info "running round=$round"
  for cwnd in $INITCWND_LIST; do
    log_info "round=$round initcwnd=$cwnd"
    enforce_initcwnd "$cwnd"

    for offset in $(seq 0 $((case_count - 1))); do
      if [[ "$ROTATE_CASE_ORDER" == "1" ]]; then
        idx=$(((round - 1 + offset) % case_count))
      else
        idx="$offset"
      fi

      entry="${cases[$idx]}"
      IFS='|' read -r case_name client_mode client_alg id_file hostkey_pref server_profile <<< "$entry"

      # Per-case port avoids config cross-talk if a previous listener was not fully replaced.
      port=$((BASE_PORT + cwnd * 10 + idx))
      cfg="$WORK_DIR/sshd_${case_name}_${cwnd}.conf"
      write_sshd_config "$cfg" "$server_profile" "$port"
      start_sshd "$cfg" "$port"

      for i in $(seq 1 "$WARMUP"); do
        run_once "$case_name" "$client_mode" "$client_alg" "$id_file" "$hostkey_pref" "$port" "$cwnd" "$round" "warmup" "$i"
      done
      for i in $(seq 1 "$ITERATIONS"); do
        run_once "$case_name" "$client_mode" "$client_alg" "$id_file" "$hostkey_pref" "$port" "$cwnd" "$round" "measure" "$i"
      done
    done
  done

  for cwnd in $INITCWND_LIST; do
    read -r A_R_P5 A_R_VAL A_R_P95 <<< "$(calc_quantiles_success_round "$cwnd" "A" "$round")"
    read -r B_R_P5 B_R_VAL B_R_P95 <<< "$(calc_quantiles_success_round "$cwnd" "B" "$round")"
    read -r C_R_P5 C_R_VAL C_R_P95 <<< "$(calc_quantiles_success_round "$cwnd" "C" "$round")"
    read -r D_R_P5 D_R_VAL D_R_P95 <<< "$(calc_quantiles_success_round "$cwnd" "D" "$round")"
    read -r E_R_P5 E_R_VAL E_R_P95 <<< "$(calc_quantiles_success_round "$cwnd" "E" "$round")"
    echo "$(us_ts),$round,$cwnd,$A_R_VAL,$B_R_VAL,$C_R_VAL,$D_R_VAL,$E_R_VAL" >> "$ROUND_TABLE_CSV"
    log_info "round=$round summary initcwnd=$cwnd A=$A_R_VAL B=$B_R_VAL C=$C_R_VAL D=$D_R_VAL E=$E_R_VAL"
  done

  log_info "round=$round done"
done

for cwnd in $INITCWND_LIST; do
  read -r A_P5 A_VAL A_P95 <<< "$(calc_quantiles_success "$cwnd" "A")"
  read -r B_P5 B_VAL B_P95 <<< "$(calc_quantiles_success "$cwnd" "B")"
  read -r C_P5 C_VAL C_P95 <<< "$(calc_quantiles_success "$cwnd" "C")"
  read -r D_P5 D_VAL D_P95 <<< "$(calc_quantiles_success "$cwnd" "D")"
  read -r E_P5 E_VAL E_P95 <<< "$(calc_quantiles_success "$cwnd" "E")"

  echo "$cwnd,A,$A_P5,$A_VAL,$A_P95" >> "$WINDOW_Q_CSV"
  echo "$cwnd,B,$B_P5,$B_VAL,$B_P95" >> "$WINDOW_Q_CSV"
  echo "$cwnd,C,$C_P5,$C_VAL,$C_P95" >> "$WINDOW_Q_CSV"
  echo "$cwnd,D,$D_P5,$D_VAL,$D_P95" >> "$WINDOW_Q_CSV"
  echo "$cwnd,E,$E_P5,$E_VAL,$E_P95" >> "$WINDOW_Q_CSV"

  echo "$cwnd,$A_VAL,$B_VAL,$C_VAL,$D_VAL,$E_VAL" >> "$TABLE_CSV"
done

cat > "$META_TXT" <<EOF
experiment=test3
objective=fig5-initcwnd-sensitivity
rtt_ms=$RTT_MS
kex=mlkem768x25519-sha256
netem_iface=$NETEM_IFACE
network_mode=$NETWORK_MODE
netns_rtt_scope=$(if [[ "$NETWORK_MODE" == "netns" ]]; then echo "bidirectional(client+server)"; else echo "single_iface"; fi)
netns_initcwnd_scope=$(if [[ "$NETWORK_MODE" == "netns" ]]; then echo "bidirectional(client+server)"; else echo "single_route(local-table)"; fi)
effective_mtu=$(if [[ "$NETWORK_MODE" == "netns" ]]; then run_root ip -n "$CLIENT_NS" -o link show "$VETH_CLIENT" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}'; else ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}'; fi)
force_disable_offload=$FORCE_DISABLE_OFFLOAD
effective_tso=$(if [[ "$NETWORK_MODE" == "netns" ]]; then echo "NA"; elif command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="tcp-segmentation-offload:" {print $2; exit}'; else echo "NA"; fi)
effective_gso=$(if [[ "$NETWORK_MODE" == "netns" ]]; then echo "NA"; elif command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="generic-segmentation-offload:" {print $2; exit}'; else echo "NA"; fi)
effective_gro=$(if [[ "$NETWORK_MODE" == "netns" ]]; then echo "NA"; elif command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="generic-receive-offload:" {print $2; exit}'; else echo "NA"; fi)
initcwnd_list=$INITCWND_LIST
iterations=$ITERATIONS
warmup=$WARMUP
rounds=$ROUNDS
rotate_case_order=$ROTATE_CASE_ORDER
execution_order=round_outer_then_initcwnd_then_case
round_summary_tz=America/New_York
raw_csv=$RAW_CSV
table_csv=$TABLE_CSV
round_table_csv=$ROUND_TABLE_CSV
window_quantile_csv=$WINDOW_Q_CSV
EOF

log_info "test3 backend completed"
log_info "artifact=$TABLE_CSV"
log_info "artifact=$ROUND_TABLE_CSV"
