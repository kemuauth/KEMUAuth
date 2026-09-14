#!/usr/bin/env bash
set -euo pipefail

EXP_ID="${EXP_ID:?EXP_ID is required (test2-C/test2-I/test2-L)}"
RTT_MS="${RTT_MS:?RTT_MS is required}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/testScripts/.work-test2/$EXP_ID}"
RESULT_DIR="${RESULT_DIR:-$ROOT_DIR/testScripts/figure4/results/$EXP_ID}"
ITERATIONS="${ITERATIONS:?ITERATIONS is required}"
WARMUP="${WARMUP:?WARMUP is required}"
ROUNDS="${ROUNDS:?ROUNDS is required}"
TEST_USER="${TEST_USER:-$(id -un)}"
TEST_HOST="${TEST_HOST:?TEST_HOST is required}"
TEST_PORT="${TEST_PORT:?TEST_PORT is required}"
KEEP_WORKDIR="${KEEP_WORKDIR:-1}"
SERVER_HOSTKEY_MODE="${SERVER_HOSTKEY_MODE:-or}"
PROFILE_TAG=""

USE_NETEM="${USE_NETEM:-0}"
NETEM_IFACE="${NETEM_IFACE:?NETEM_IFACE is required}"
NETEM_TARGET_MTU="${NETEM_TARGET_MTU:-1500}"
FORCE_DISABLE_OFFLOAD="${FORCE_DISABLE_OFFLOAD:-1}"
SUDO_BIN="${SUDO_BIN:-sudo}"
SUDO_NONINTERACTIVE="${SUDO_NONINTERACTIVE:-1}"
NETEM_DELAY_MODE="${NETEM_DELAY_MODE:-half_rtt}"

SSH_BIN="${SSH_BIN:-$ROOT_DIR/ssh}"
SSHD_BIN="${SSHD_BIN:-$ROOT_DIR/sshd}"
SSH_KEYGEN_BIN="${SSH_KEYGEN_BIN:-$ROOT_DIR/ssh-keygen}"
SSHD_SESSION_BIN="${SSHD_SESSION_BIN:-$ROOT_DIR/sshd-session}"
SSHD_AUTH_BIN="${SSHD_AUTH_BIN:-$ROOT_DIR/sshd-auth}"

ID_ED25519_FILE="${ID_ED25519_FILE:-$WORK_DIR/id_ed25519}"
ID_MD65_FILE="${ID_MD65_FILE:-$WORK_DIR/id_mldsa65}"
ID_SD192F_FILE="${ID_SD192F_FILE:-$WORK_DIR/id_slhdsa192f}"
ID_MD65_AND_FILE="${ID_MD65_AND_FILE:-$WORK_DIR/id_ed25519_mldsa65}"
ID_SD192F_AND_FILE="${ID_SD192F_AND_FILE:-$WORK_DIR/id_ed25519_slhdsapuresha2192f}"
ID_MK768_FILE="${ID_MK768_FILE:-$ROOT_DIR/testScripts/.work-kem/id_mlkem768}"

HOSTKEY_ED25519_FILE="${HOSTKEY_ED25519_FILE:-$WORK_DIR/ssh_host_ed25519_key}"
HOSTKEY_MD65_FILE="${HOSTKEY_MD65_FILE:-$WORK_DIR/ssh_host_mldsa65_key}"
HOSTKEY_SD192F_FILE="${HOSTKEY_SD192F_FILE:-$WORK_DIR/ssh_host_slhdsa192f_key}"
HOSTKEY_MD65_AND_FILE="${HOSTKEY_MD65_AND_FILE:-$WORK_DIR/ssh_host_ed25519_mldsa65_key}"
HOSTKEY_SD192F_AND_FILE="${HOSTKEY_SD192F_AND_FILE:-$WORK_DIR/ssh_host_ed25519_slhdsapuresha2192f_key}"

if [[ ! -x "$SSH_BIN" || ! -x "$SSHD_BIN" || ! -x "$SSH_KEYGEN_BIN" ||
      ! -x "$SSHD_SESSION_BIN" || ! -x "$SSHD_AUTH_BIN" ]]; then
  echo "[ERR] missing binaries: ssh/sshd/ssh-keygen/sshd-session/sshd-auth"
  exit 1
fi

mkdir -p "$WORK_DIR" "$RESULT_DIR"
RAW_CSV="$RESULT_DIR/raw_runs.csv"
SUMMARY_CSV="$RESULT_DIR/summary.csv"
MANIFEST_CSV="$RESULT_DIR/cases_manifest.csv"
META_TXT="$RESULT_DIR/metadata.txt"
ROUND_MEAN_CSV="$RESULT_DIR/round_means_append.csv"
KNOWN_HOSTS="$WORK_DIR/known_hosts"
AUTHORIZED_KEYS="$WORK_DIR/authorized_keys"
AUTHORIZED_KEM_KEYS="$WORK_DIR/authorized_kem_keys"
SSHD_LOG="$WORK_DIR/sshd.log"

case "$EXP_ID" in
  test2-C)
    PROFILE_TAG="test2-C"
    ;;
  test2-I)
    PROFILE_TAG="test2-I"
    ;;
  test2-L)
    PROFILE_TAG="test2-L"
    ;;
  *)
    echo "[ERR] unsupported EXP_ID=$EXP_ID"
    exit 1
    ;;
esac

SSHD_PID=""
ORIG_IFACE_MTU=""
IFACE_MTU_TOUCHED=0
ORIG_LO_TSO=""
ORIG_LO_GSO=""
ORIG_LO_GRO=""
OFFLOAD_TOUCHED=0
cleanup() {
  if [[ -n "$SSHD_PID" ]] && kill -0 "$SSHD_PID" 2>/dev/null; then
    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi
  if [[ "$IFACE_MTU_TOUCHED" == "1" && -n "$ORIG_IFACE_MTU" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      ip link set dev "$NETEM_IFACE" mtu "$ORIG_IFACE_MTU" >/dev/null 2>&1 || true
    elif command -v "$SUDO_BIN" >/dev/null 2>&1 && "$SUDO_BIN" -n true >/dev/null 2>&1; then
      "$SUDO_BIN" -n ip link set dev "$NETEM_IFACE" mtu "$ORIG_IFACE_MTU" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$OFFLOAD_TOUCHED" == "1" && "$NETEM_IFACE" == "lo" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      ethtool -K "$NETEM_IFACE" tso "$ORIG_LO_TSO" gso "$ORIG_LO_GSO" gro "$ORIG_LO_GRO" >/dev/null 2>&1 || true
    elif command -v "$SUDO_BIN" >/dev/null 2>&1 && "$SUDO_BIN" -n true >/dev/null 2>&1; then
      "$SUDO_BIN" -n ethtool -K "$NETEM_IFACE" tso "$ORIG_LO_TSO" gso "$ORIG_LO_GSO" gro "$ORIG_LO_GRO" >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$USE_NETEM" == "1" && -n "$NETEM_IFACE" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    elif command -v "$SUDO_BIN" >/dev/null 2>&1 && "$SUDO_BIN" -n true >/dev/null 2>&1; then
      "$SUDO_BIN" -n tc qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
    fi
  fi
  if [[ "$KEEP_WORKDIR" != "1" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

get_offload_state() {
  local feature="$1"
  ethtool -k "$NETEM_IFACE" 2>/dev/null | awk -v f="$feature" '$1 == f":" {print $2; exit}'
}

enforce_lo_offload_if_requested() {
  local ethtool_cmd

  if [[ "$USE_NETEM" != "1" ]]; then
    return 0
  fi
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

  if [[ "$ORIG_LO_TSO" == "off" && "$ORIG_LO_GSO" == "off" && "$ORIG_LO_GRO" == "off" ]]; then
    echo "[INFO] lo offload already disabled"
    return 0
  fi

  echo "[INFO] Disabling lo offload: tso=$ORIG_LO_TSO gso=$ORIG_LO_GSO gro=$ORIG_LO_GRO"
  if [[ "$(id -u)" -eq 0 ]]; then
    ethtool -K "$NETEM_IFACE" tso off gso off gro off
  else
    if ! command -v "$SUDO_BIN" >/dev/null 2>&1; then
      echo "[ERR] disabling lo offload requires root or sudo when USE_NETEM=1"
      exit 1
    fi
    if [[ "$SUDO_NONINTERACTIVE" == "1" ]]; then
      if ! "$SUDO_BIN" -n true >/dev/null 2>&1; then
        echo "[ERR] disabling lo offload requires root or passwordless sudo when SUDO_NONINTERACTIVE=1"
        exit 1
      fi
      ethtool_cmd="$SUDO_BIN -n ethtool"
    else
      ethtool_cmd="$SUDO_BIN ethtool"
    fi
    # shellcheck disable=SC2086
    $ethtool_cmd -K "$NETEM_IFACE" tso off gso off gro off
  fi
  OFFLOAD_TOUCHED=1
}

enforce_netem_iface_mtu_if_requested() {
  local current_mtu
  local ip_bin

  if [[ "$USE_NETEM" != "1" ]]; then
    return 0
  fi
  if [[ -z "$NETEM_IFACE" ]]; then
    echo "[ERR] USE_NETEM=1 requires NETEM_IFACE"
    exit 1
  fi
  if ! command -v ip >/dev/null 2>&1; then
    echo "[ERR] ip not found in PATH"
    exit 1
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    current_mtu="$(ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  else
    if ! command -v "$SUDO_BIN" >/dev/null 2>&1; then
      echo "[ERR] setting MTU requires root or sudo when USE_NETEM=1"
      exit 1
    fi
    if [[ "$SUDO_NONINTERACTIVE" == "1" ]]; then
      if ! "$SUDO_BIN" -n true >/dev/null 2>&1; then
        echo "[ERR] setting MTU requires root or passwordless sudo when USE_NETEM=1"
        exit 1
      fi
      current_mtu="$("$SUDO_BIN" -n ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
      ip_bin="$SUDO_BIN -n ip"
    else
      current_mtu="$("$SUDO_BIN" ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
      ip_bin="$SUDO_BIN ip"
    fi
  fi

  if [[ -z "$current_mtu" ]]; then
    echo "[ERR] failed to query MTU for iface=$NETEM_IFACE"
    exit 1
  fi

  ORIG_IFACE_MTU="$current_mtu"
  if [[ "$current_mtu" == "$NETEM_TARGET_MTU" ]]; then
    echo "[INFO] iface=$NETEM_IFACE MTU already $NETEM_TARGET_MTU"
    return 0
  fi

  echo "[INFO] Adjusting iface=$NETEM_IFACE MTU: $current_mtu -> $NETEM_TARGET_MTU"
  if [[ "$(id -u)" -eq 0 ]]; then
    ip link set dev "$NETEM_IFACE" mtu "$NETEM_TARGET_MTU"
  else
    # shellcheck disable=SC2086
    $ip_bin link set dev "$NETEM_IFACE" mtu "$NETEM_TARGET_MTU"
  fi
  IFACE_MTU_TOUCHED=1
}

apply_netem_if_requested() {
  local delay_ms
  local tc_bin

  if [[ "$USE_NETEM" != "1" ]]; then
    return 0
  fi
  if [[ -z "$NETEM_IFACE" ]]; then
    echo "[ERR] USE_NETEM=1 requires NETEM_IFACE"
    exit 1
  fi

  if ! command -v tc >/dev/null 2>&1; then
    echo "[ERR] tc not found in PATH"
    exit 1
  fi

  if [[ "$NETEM_DELAY_MODE" == "half_rtt" ]]; then
    delay_ms="$(awk -v rtt="$RTT_MS" 'BEGIN { printf "%.3f", rtt/2.0 }')"
  else
    delay_ms="$RTT_MS"
  fi

  tc_bin="tc"
  if [[ "$(id -u)" -ne 0 ]]; then
    if ! command -v "$SUDO_BIN" >/dev/null 2>&1; then
      echo "[ERR] netem requires root or sudo when USE_NETEM=1"
      exit 1
    fi
    if [[ "$SUDO_NONINTERACTIVE" == "1" ]]; then
      if ! "$SUDO_BIN" -n true >/dev/null 2>&1; then
        echo "[ERR] netem requires root or passwordless sudo when USE_NETEM=1"
        echo "[ERR] current user cannot run '$SUDO_BIN -n tc ...'"
        exit 1
      fi
      tc_bin="$SUDO_BIN -n tc"
    else
      tc_bin="$SUDO_BIN tc"
    fi
  fi

  # shellcheck disable=SC2086
  $tc_bin qdisc del dev "$NETEM_IFACE" root 2>/dev/null || true
  # shellcheck disable=SC2086
  $tc_bin qdisc add dev "$NETEM_IFACE" root netem delay "${delay_ms}ms"
}

extract_kem_public() {
  local f="$1"
  awk 'BEGIN{IGNORECASE=1} $1 ~ /^public$/ {print $2; exit}' "$f"
}

supports_ssh_key_alg() {
  local alg="$1"
  "$SSH_BIN" -Q key 2>/dev/null | grep -Fxq "$alg"
}

key_file_matches_alg() {
  local alg="$1"
  local path="$2"
  local pub="${path}.pub"
  local actual=""

  [[ -f "$path" && -f "$pub" ]] || return 1
  actual="$(awk 'NR==1{print $1}' "$pub" 2>/dev/null || true)"
  [[ "$actual" == "$alg" ]]
}

ensure_pubkey_identity() {
  local alg="$1"
  local path="$2"

  if key_file_matches_alg "$alg" "$path"; then
    return 0
  fi
  rm -f "$path" "$path.pub"
  if ! supports_ssh_key_alg "$alg"; then
    return 1
  fi
  mkdir -p "$(dirname "$path")"
  "$SSH_KEYGEN_BIN" -q -t "$alg" -N "" -f "$path" >/dev/null
}

ensure_hostkey() {
  local alg="$1"
  local path="$2"

  if key_file_matches_alg "$alg" "$path"; then
    return 0
  fi
  rm -f "$path" "$path.pub"
  if ! supports_ssh_key_alg "$alg"; then
    return 1
  fi
  mkdir -p "$(dirname "$path")"
  "$SSH_KEYGEN_BIN" -q -t "$alg" -N "" -f "$path" >/dev/null
}

ensure_kem_identity() {
  local alg="$1"
  local path="$2"

  if [[ -f "$path" ]]; then
    return 0
  fi
  case "$alg" in
    ML-KEM-768)
      mkdir -p "$(dirname "$path")"
      bash "$ROOT_DIR/testScripts/backends/generate_kem_identity.sh" "$path" >/dev/null
      return 0
      ;;
  esac
  return 1
}

ensure_ed25519_keys() {
  if [[ ! -f "$HOSTKEY_ED25519_FILE" ]]; then
    mkdir -p "$(dirname "$HOSTKEY_ED25519_FILE")"
    "$SSH_KEYGEN_BIN" -q -t ed25519 -N "" -f "$HOSTKEY_ED25519_FILE" >/dev/null
  fi
  if [[ ! -f "$ID_ED25519_FILE" ]]; then
    mkdir -p "$(dirname "$ID_ED25519_FILE")"
    "$SSH_KEYGEN_BIN" -q -t ed25519 -N "" -f "$ID_ED25519_FILE" >/dev/null
  fi
}

prepare_authorized_files() {
  : > "$AUTHORIZED_KEYS"
  : > "$AUTHORIZED_KEM_KEYS"
  for key in "$ID_ED25519_FILE" "$ID_MD65_FILE" "$ID_SD192F_FILE" "$ID_MD65_AND_FILE" "$ID_SD192F_AND_FILE"; do
    if [[ -n "$key" && -f "$key.pub" ]]; then
      cat "$key.pub" >> "$AUTHORIZED_KEYS"
    fi
  done
  if [[ -f "$ID_MK768_FILE" ]]; then
    pub="$(extract_kem_public "$ID_MK768_FILE" || true)"
    if [[ -n "$pub" ]]; then
      printf 'ML-KEM-768 %s\n' "$pub" >> "$AUTHORIZED_KEM_KEYS"
    fi
  fi
}

write_sshd_config() {
  local profile="$1"
  local auth_chain="$2"
  local hostkey_mode="$3"
  local cfg="$WORK_DIR/sshd_${profile}.conf"
  {
    echo "Port $TEST_PORT"
    echo "ListenAddress $TEST_HOST"
    echo "PidFile $WORK_DIR/sshd.pid"
    echo "LogLevel ERROR"
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
    echo "ChallengeResponseAuthentication no"
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication yes"
    echo "PubkeyAcceptedAlgorithms ssh-ed25519,ssh-mldsa-65,ssh-slhdsapuresha2192f,ssh-ed25519-mldsa-65,ssh-ed25519-slhdsapuresha2192f"
    echo "KEMAuthentication yes"
    echo "KEMAuthAlgorithms ML-KEM-768"
    echo "KexAlgorithms mlkem768x25519-sha256"
    case "$auth_chain" in
      publickey)
        echo "AuthenticationMethods publickey"
        ;;
      publickey-hybrid-and)
        echo "AuthenticationMethods publickey-hybrid-and"
        ;;
      publickey-kem-and)
        echo "AuthenticationMethods publickey-kem-and"
        ;;
      publickey2)
        echo "AuthenticationMethods publickey,publickey"
        ;;
      publickey+kem)
        echo "AuthenticationMethods publickey,publickey-kem"
        ;;
      kem+publickey)
        echo "AuthenticationMethods publickey-kem,publickey"
        ;;
      publickey-kem)
        echo "AuthenticationMethods publickey-kem"
        ;;
      *)
        echo "[ERR] unknown auth chain: $auth_chain" >&2
        exit 1
        ;;
    esac
    echo "AuthorizedKeysFile $AUTHORIZED_KEYS"
    echo "AuthorizedKEMKeysFile $AUTHORIZED_KEM_KEYS"
    echo "StrictModes no"
    echo "SshdSessionPath $SSHD_SESSION_BIN"
    echo "SshdAuthPath $SSHD_AUTH_BIN"
    case "$profile" in
      ed25519)
        echo "HostKey $HOSTKEY_ED25519_FILE"
        echo "HostKeyAlgorithms ssh-ed25519"
        ;;
      md65_ed25519)
        if [[ "$hostkey_mode" == "and" ]]; then
          echo "HostKey $HOSTKEY_MD65_AND_FILE"
          echo "HostKeyAlgorithms ssh-ed25519-mldsa-65"
        else
          echo "HostKey $HOSTKEY_ED25519_FILE"
          echo "HostKeyAlgorithms ssh-mldsa-65,ssh-ed25519"
          [[ -n "$HOSTKEY_MD65_FILE" ]] && echo "HostKey $HOSTKEY_MD65_FILE"
        fi
        ;;
      sd192f_ed25519)
        if [[ "$hostkey_mode" == "and" ]]; then
          echo "HostKey $HOSTKEY_SD192F_AND_FILE"
          echo "HostKeyAlgorithms ssh-ed25519-slhdsapuresha2192f"
        else
          echo "HostKey $HOSTKEY_ED25519_FILE"
          echo "HostKeyAlgorithms ssh-slhdsapuresha2192f,ssh-ed25519"
          [[ -n "$HOSTKEY_SD192F_FILE" ]] && echo "HostKey $HOSTKEY_SD192F_FILE"
        fi
        ;;
      md65)
        echo "HostKeyAlgorithms ssh-mldsa-65"
        [[ -n "$HOSTKEY_MD65_FILE" ]] && echo "HostKey $HOSTKEY_MD65_FILE"
        ;;
      *)
        echo "[ERR] unknown hostkey profile: $profile" >&2
        exit 1
        ;;
    esac
  } > "$cfg"
  echo "$cfg"
}

start_sshd() {
  local cfg="$1"
  local banner=""
  local pid cmd
  local -a stale_pids=()
  if [[ -n "$SSHD_PID" ]] && kill -0 "$SSHD_PID" 2>/dev/null; then
    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
  fi

  mapfile -t stale_pids < <(
    ss -ltnp 2>/dev/null | awk -v p=":$TEST_PORT" '
      $4 ~ p"$" {
        while (match($0, /pid=[0-9]+/)) {
          print substr($0, RSTART + 4, RLENGTH - 4)
          $0 = substr($0, RSTART + RLENGTH)
        }
      }
    ' | sort -u
  )
  for pid in "${stale_pids[@]}"; do
    [[ -n "$pid" ]] || continue
    cmd="$(ps -p "$pid" -o args= 2>/dev/null || true)"
    if [[ "$cmd" == *"$SSHD_BIN"* ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    else
      echo "[ERR] test port $TEST_PORT already in use by pid=$pid: $cmd"
      echo "[ERR] please free the port or set TEST_PORT to an unused value"
      return 1
    fi
  done

  "$SSHD_BIN" -f "$cfg" -E "$SSHD_LOG" -D &
  SSHD_PID=$!
  for _ in $(seq 1 200); do
    if { exec 3<>"/dev/tcp/$TEST_HOST/$TEST_PORT"; } 2>/dev/null; then
      banner=""
      if read -r -t 0.2 banner <&3 2>/dev/null && [[ "$banner" == SSH-* ]]; then
        exec 3>&- || true
        exec 3<&- || true
        return 0
      fi
      exec 3>&- || true
      exec 3<&- || true
    fi
    read -r -t 0.05 _ || true
  done
  echo "[ERR] sshd start timeout: $cfg"
  return 1
}

run_once() {
  local case_name="$1" round="$2" phase="$3" iter="$4" auth_chain="$5" impl_alg="$6" id_spec="$7" client_hostkey_pref="$8"
  local id1="" id2=""
  local rc=0 start_ns end_ns delta_ms
  IFS=';' read -r id1 id2 <<< "$id_spec"
  start_ns="$(date +%s%N)"
  if [[ "$auth_chain" == "publickey" || "$auth_chain" == "publickey-hybrid-and" ]]; then
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications="$auth_chain" \
      -o PubkeyAcceptedAlgorithms="$impl_alg" \
      -o IdentityFile="$id1" \
      -o KEMAuthentication=no \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  elif [[ "$auth_chain" == "publickey2" ]]; then
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications=publickey,publickey \
      -o PubkeyAcceptedAlgorithms="$impl_alg,ssh-ed25519" \
      -o IdentityFile="$id1" \
      -o IdentityFile="$id2" \
      -o KEMAuthentication=no \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  elif [[ "$auth_chain" == "kem+publickey" ]]; then
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications=publickey-kem,publickey \
      -o PubkeyAuthentication=yes \
      -o PubkeyAcceptedAlgorithms=ssh-ed25519 \
      -o KEMAuthentication=yes \
      -o KEMAuthAlgorithms=ML-KEM-768 \
      -o IdentityKEMFile="$id1" \
      -o IdentityFile="$id2" \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  elif [[ "$auth_chain" == "publickey-kem-and" ]]; then
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications=publickey-kem-and \
      -o PubkeyAuthentication=yes \
      -o PubkeyAcceptedAlgorithms=ssh-ed25519 \
      -o KEMAuthentication=yes \
      -o KEMAuthAlgorithms=ML-KEM-768 \
      -o IdentityFile="$id1" \
      -o IdentityKEMFile="$id2" \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  elif [[ "$auth_chain" == "publickey+kem" ]]; then
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications=publickey,publickey-kem \
      -o PubkeyAuthentication=yes \
      -o PubkeyAcceptedAlgorithms=ssh-ed25519 \
      -o KEMAuthentication=yes \
      -o KEMAuthAlgorithms=ML-KEM-768 \
      -o IdentityFile="$id1" \
      -o IdentityKEMFile="$id2" \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  else
    "$SSH_BIN" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o BatchMode=yes \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      -o KbdInteractiveAuthentication=no \
      -o ConnectTimeout=5 \
      -o KexAlgorithms=mlkem768x25519-sha256 \
      -o HostKeyAlgorithms="$client_hostkey_pref" \
      -o PreferredAuthentications=publickey-kem \
      -o PubkeyAuthentication=no \
      -o KEMAuthentication=yes \
      -o KEMAuthAlgorithms=ML-KEM-768 \
      -o IdentityKEMFile="$id1" \
      -p "$TEST_PORT" \
      "$TEST_USER@$TEST_HOST" true >/dev/null 2>&1 || rc=$?
  fi
  end_ns="$(date +%s%N)"
  delta_ms=$(awk -v ns="$((end_ns-start_ns))" 'BEGIN { printf "%.3f", ns/1000000.0 }')
  echo "$case_name,$round,$phase,$iter,$auth_chain,$impl_alg,$rc,$delta_ms" >> "$RAW_CSV"
}

summarize_case() {
  local case_name="$1" suite="$2" server_suite="$3" status="$4" reason="$5"
  local total fail success mean p50 p95
  total=$(awk -F, -v c="$case_name" '$1==c && $3=="measure" {n++} END{print n+0}' "$RAW_CSV")
  fail=$(awk -F, -v c="$case_name" '$1==c && $3=="measure" && $7!=0 {n++} END{print n+0}' "$RAW_CSV")
  success=$((total-fail))
  if (( success > 0 )); then
    read -r mean p50 p95 <<EOFST
$(awk -F, -v c="$case_name" '$1==c && $3=="measure" && $7==0 {print $8}' "$RAW_CSV" | sort -n | awk '{a[NR]=$1;s+=$1} END{n=NR;if(n==0){print "NA NA NA";exit} p50i=int(0.50*n+0.999999);if(p50i<1)p50i=1;if(p50i>n)p50i=n; p95i=int(0.95*n+0.999999);if(p95i<1)p95i=1;if(p95i>n)p95i=n; printf "%.3f %.3f %.3f\n", s/n,a[p50i],a[p95i]}')
EOFST
  else
    mean="NA"; p50="NA"; p95="NA"
  fi
  fail_rate=$(awk -v f="$fail" -v t="$total" 'BEGIN{if(t==0) print "NA"; else printf "%.4f", f/t}')
  echo "$case_name,$suite,$server_suite,$status,$reason,$mean,$p50,$p95,$fail_rate,0.0000,$total,$success,$fail" >> "$SUMMARY_CSV"
}

append_round_mean() {
  local case_name="$1" client_suite="$2" server_suite="$3" round="$4"
  local mean success total fail

  total=$(awk -F, -v c="$case_name" -v r="$round" '$1==c && $2==r && $3=="measure" {n++} END{print n+0}' "$RAW_CSV")
  fail=$(awk -F, -v c="$case_name" -v r="$round" '$1==c && $2==r && $3=="measure" && $7!=0 {n++} END{print n+0}' "$RAW_CSV")
  success=$((total-fail))
  if (( success > 0 )); then
    mean=$(awk -F, -v c="$case_name" -v r="$round" '$1==c && $2==r && $3=="measure" && $7==0 {s+=$8;n++} END{if(n==0) print "NA"; else printf "%.3f", s/n}' "$RAW_CSV")
  else
    mean="NA"
  fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(TZ=America/New_York date +%Y-%m-%dT%H:%M:%S%z)" "$EXP_ID" "$round" "$case_name" "$client_suite" "$server_suite" "$mean" "$success" "$total" >> "$ROUND_MEAN_CSV"
}

ensure_ed25519_keys
ensure_pubkey_identity "ssh-mldsa-65" "$ID_MD65_FILE" || true
ensure_pubkey_identity "ssh-slhdsapuresha2192f" "$ID_SD192F_FILE" || true
ensure_pubkey_identity "ssh-ed25519-mldsa-65" "$ID_MD65_AND_FILE" || true
ensure_pubkey_identity "ssh-ed25519-slhdsapuresha2192f" "$ID_SD192F_AND_FILE" || true
ensure_hostkey "ssh-mldsa-65" "$HOSTKEY_MD65_FILE" || true
ensure_hostkey "ssh-slhdsapuresha2192f" "$HOSTKEY_SD192F_FILE" || true
ensure_hostkey "ssh-ed25519-mldsa-65" "$HOSTKEY_MD65_AND_FILE" || true
ensure_hostkey "ssh-ed25519-slhdsapuresha2192f" "$HOSTKEY_SD192F_AND_FILE" || true
ensure_kem_identity "ML-KEM-768" "$ID_MK768_FILE" || true
prepare_authorized_files
enforce_netem_iface_mtu_if_requested
enforce_lo_offload_if_requested
apply_netem_if_requested

echo "case,round,phase,iter,auth_mode,impl_alg,rc,latency_ms" > "$RAW_CSV"
echo "case,client_suite,server_suite,status,reason,mean_ms,p50_ms,p95_ms,failure_rate,retry_rate,total,success,fail" > "$SUMMARY_CSV"
echo "case,client_suite,server_profile,client_auth_chain,server_auth_chain,impl_alg,id_spec,client_hostkey_pref" > "$MANIFEST_CSV"
echo "ts_us,experiment,round,case,client_alg,server_alg,mean_ms,success,total" > "$ROUND_MEAN_CSV"

# case_name|client_suite|server_profile|client_auth_chain|server_auth_chain|impl_alg|id_spec|client_hostkey_pref|server_suite|required_paths
if [[ "$SERVER_HOSTKEY_MODE" == "and" ]]; then
  cases=(
    "classic|ssh-ed25519|ed25519|publickey|publickey|ssh-ed25519|$ID_ED25519_FILE|ssh-ed25519|ssh-ed25519|"
    "hybrid_md65_ed25519|ssh-ed25519+ssh-mldsa-65|md65_ed25519|publickey-hybrid-and|publickey-hybrid-and|ssh-ed25519-mldsa-65|$ID_MD65_AND_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_AND_FILE"
    "hybrid_sd192f_ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|sd192f_ed25519|publickey-hybrid-and|publickey-hybrid-and|ssh-ed25519-slhdsapuresha2192f|$ID_SD192F_AND_FILE|ssh-ed25519-slhdsapuresha2192f,ssh-ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|$HOSTKEY_SD192F_AND_FILE"
    "migration_kem768_server_md65_ed25519|ssh-ed25519+ML-KEM-768|md65_ed25519|publickey-kem-and|publickey-kem-and|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_AND_FILE"
    "migration_kem768_server_sd192f_ed25519|ssh-ed25519+ML-KEM-768|sd192f_ed25519|publickey-kem-and|publickey-kem-and|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-slhdsapuresha2192f,ssh-ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|$HOSTKEY_SD192F_AND_FILE"
    "chain_ed25519_to_md65|ssh-ed25519->ssh-mldsa-65|md65_ed25519|publickey2|publickey2|ssh-mldsa-65|$ID_ED25519_FILE;$ID_MD65_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_AND_FILE"
    "chain_ed25519_to_mk768|ssh-ed25519->ML-KEM-768|md65_ed25519|publickey+kem|publickey+kem|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_AND_FILE"
    "pure_pq_userauth_path|ML-KEM-768|md65|publickey-kem|publickey-kem|ML-KEM-768|$ID_MK768_FILE|ssh-mldsa-65|ssh-mldsa-65|$HOSTKEY_MD65_FILE"
  )
else
  cases=(
    "classic|ssh-ed25519|ed25519|publickey|publickey|ssh-ed25519|$ID_ED25519_FILE|ssh-ed25519|ssh-ed25519|"
    "hybrid_md65_ed25519|ssh-ed25519+ssh-mldsa-65|md65_ed25519|publickey-hybrid-and|publickey-hybrid-and|ssh-ed25519-mldsa-65|$ID_MD65_AND_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_FILE"
    "hybrid_sd192f_ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|sd192f_ed25519|publickey-hybrid-and|publickey-hybrid-and|ssh-ed25519-slhdsapuresha2192f|$ID_SD192F_AND_FILE|ssh-ed25519-slhdsapuresha2192f,ssh-ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|$HOSTKEY_SD192F_FILE"
    "migration_kem768_server_md65_ed25519|ssh-ed25519+ML-KEM-768|md65_ed25519|publickey-kem-and|publickey-kem-and|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_FILE"
    "migration_kem768_server_sd192f_ed25519|ssh-ed25519+ML-KEM-768|sd192f_ed25519|publickey-kem-and|publickey-kem-and|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-slhdsapuresha2192f,ssh-ed25519|ssh-ed25519+ssh-slhdsapuresha2192f|$HOSTKEY_SD192F_FILE"
    "chain_ed25519_to_md65|ssh-ed25519->ssh-mldsa-65|md65_ed25519|publickey2|publickey2|ssh-mldsa-65|$ID_ED25519_FILE;$ID_MD65_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_FILE"
    "chain_ed25519_to_mk768|ssh-ed25519->ML-KEM-768|md65_ed25519|publickey+kem|publickey+kem|ssh-ed25519+ML-KEM-768|$ID_ED25519_FILE;$ID_MK768_FILE|ssh-ed25519-mldsa-65,ssh-ed25519|ssh-ed25519+ssh-mldsa-65|$HOSTKEY_MD65_FILE"
    "pure_pq_userauth_path|ML-KEM-768|md65|publickey-kem|publickey-kem|ML-KEM-768|$ID_MK768_FILE|ssh-mldsa-65|ssh-mldsa-65|$HOSTKEY_MD65_FILE"
  )
fi

runnable_cases=()
declare -A CASE_STATUS
declare -A CASE_REASON

for entry in "${cases[@]}"; do
  IFS='|' read -r case_name client_suite server_profile client_auth_chain server_auth_chain impl_alg id_spec client_hk_pref server_suite required_paths <<< "$entry"
  echo "$case_name,$client_suite,$server_profile,$client_auth_chain,$server_auth_chain,$impl_alg,$id_spec,$client_hk_pref" >> "$MANIFEST_CSV"

  if [[ "$server_profile" == "md65_ed25519" || "$server_profile" == "md65" ]]; then
    if [[ "$SERVER_HOSTKEY_MODE" == "and" && "$server_profile" == "md65_ed25519" ]]; then
      if ! supports_ssh_key_alg "ssh-ed25519-mldsa-65"; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "ssh-ed25519-mldsa-65 not supported by current build"
        continue
      fi
      if [[ ! -f "$HOSTKEY_MD65_AND_FILE" ]]; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate md65 and-mode hostkey"
        continue
      fi
    else
      if ! supports_ssh_key_alg "ssh-mldsa-65"; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "ssh-mldsa-65 not supported by current build"
        continue
      fi
      if [[ ! -f "$HOSTKEY_MD65_FILE" ]]; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate md65 hostkey"
        continue
      fi
    fi
  fi
  if [[ "$server_profile" == "sd192f_ed25519" ]]; then
    if [[ "$SERVER_HOSTKEY_MODE" == "and" ]]; then
      if ! supports_ssh_key_alg "ssh-ed25519-slhdsapuresha2192f"; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "ssh-ed25519-slhdsapuresha2192f not supported by current build"
        continue
      fi
      if [[ ! -f "$HOSTKEY_SD192F_AND_FILE" ]]; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate sd192f and-mode hostkey"
        continue
      fi
    else
      if ! supports_ssh_key_alg "ssh-slhdsapuresha2192f"; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "ssh-slhdsapuresha2192f not supported by current build"
        continue
      fi
      if [[ ! -f "$HOSTKEY_SD192F_FILE" ]]; then
        summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate sd192f hostkey"
        continue
      fi
    fi
  fi
  IFS=';' read -r id1 id2 <<< "$id_spec"

  if [[ "$client_auth_chain" == "publickey-kem" && ! -f "$id1" ]]; then
    summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate ML-KEM-768 identity"
    continue
  fi
  if [[ "$client_auth_chain" == "publickey" ]]; then
    if [[ ! -f "$id1" || ! -f "$id1.pub" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to auto-generate ed25519 identity"
      continue
    fi
  fi
  if [[ "$client_auth_chain" == "publickey-hybrid-and" ]]; then
    if [[ ! -f "$id1" || ! -f "$id1.pub" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to prepare publickey-hybrid-and identity"
      continue
    fi
    if ! supports_ssh_key_alg "$impl_alg"; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "$impl_alg not supported by current build"
      continue
    fi
  fi
  if [[ "$client_auth_chain" == "publickey2" ]]; then
    if [[ ! -f "$id1" || ! -f "$id1.pub" || ! -f "$id2" || ! -f "$id2.pub" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to prepare dual publickey identities"
      continue
    fi
  fi
  if [[ "$client_auth_chain" == "kem+publickey" ]]; then
    if [[ ! -f "$id1" || ! -f "$id2" || ! -f "$id2.pub" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to prepare kem+publickey identities"
      continue
    fi
  fi
  if [[ "$client_auth_chain" == "publickey-kem-and" ]]; then
    if [[ ! -f "$id1" || ! -f "$id1.pub" || ! -f "$id2" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to prepare publickey-kem-and identities"
      continue
    fi
  fi
  if [[ "$client_auth_chain" == "publickey+kem" ]]; then
    if [[ ! -f "$id1" || ! -f "$id1.pub" || ! -f "$id2" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "UNSUPPORTED" "failed to prepare publickey+kem identities"
      continue
    fi
  fi

  runnable_cases+=("$entry")
  CASE_STATUS["$case_name"]="RUNNABLE"
  CASE_REASON["$case_name"]=""
done

runnable_count="${#runnable_cases[@]}"
if (( runnable_count > 0 )); then
  for round in $(seq 1 "$ROUNDS"); do
    # Round-robin rotate test order by round index: 1..N, 2..N,1, ..., N,1..N-1.
    for offset in $(seq 0 $((runnable_count - 1))); do
      idx=$(((round - 1 + offset) % runnable_count))
      entry="${runnable_cases[$idx]}"
      IFS='|' read -r case_name client_suite server_profile client_auth_chain server_auth_chain impl_alg id_spec client_hk_pref server_suite required_paths <<< "$entry"

      if [[ "${CASE_STATUS[$case_name]}" != "RUNNABLE" ]]; then
        continue
      fi

      cfg="$(write_sshd_config "$server_profile" "$server_auth_chain" "$SERVER_HOSTKEY_MODE")"
      if ! start_sshd "$cfg"; then
        CASE_STATUS["$case_name"]="SKIP"
        CASE_REASON["$case_name"]="failed to start sshd in round $round"
        continue
      fi

      for i in $(seq 1 "$WARMUP"); do
        run_once "$case_name" "$round" "warmup" "$i" "$client_auth_chain" "$impl_alg" "$id_spec" "$client_hk_pref"
      done
      for i in $(seq 1 "$ITERATIONS"); do
        run_once "$case_name" "$round" "measure" "$i" "$client_auth_chain" "$impl_alg" "$id_spec" "$client_hk_pref"
      done
      append_round_mean "$case_name" "$client_suite" "$server_suite" "$round"
    done
    echo "[PROGRESS] round=$round done"
  done

  for entry in "${runnable_cases[@]}"; do
    IFS='|' read -r case_name client_suite server_profile client_auth_chain server_auth_chain impl_alg id_spec client_hk_pref server_suite required_paths <<< "$entry"

    if [[ "${CASE_STATUS[$case_name]}" == "SKIP" ]]; then
      summarize_case "$case_name" "$client_suite" "$server_suite" "SKIP" "${CASE_REASON[$case_name]}"
      continue
    fi

    fail=$(awk -F, -v c="$case_name" '$1==c && $3=="measure" && $7!=0 {n++} END{print n+0}' "$RAW_CSV")
    if (( fail == 0 )); then
      summarize_case "$case_name" "$client_suite" "$server_suite" "PASS" ""
    else
      summarize_case "$case_name" "$client_suite" "$server_suite" "FAIL" "non-zero failures"
    fi
    echo "[PROGRESS] case=$case_name done"
  done
fi

cat > "$META_TXT" <<EOF
experiment=$PROFILE_TAG
kex=mlkem768x25519-sha256
rtt_target_ms=$RTT_MS
netem_delay_mode=$NETEM_DELAY_MODE
netem_applied_delay_ms=$(if [[ "$USE_NETEM" == "1" ]]; then if [[ "$NETEM_DELAY_MODE" == "half_rtt" ]]; then awk -v rtt="$RTT_MS" 'BEGIN { printf "%.3f", rtt/2.0 }'; else echo "$RTT_MS"; fi; else echo "0"; fi)
use_netem=$USE_NETEM
netem_iface=${NETEM_IFACE:-NA}
netem_target_mtu=$NETEM_TARGET_MTU
effective_mtu=$(if [[ "$USE_NETEM" == "1" && -n "$NETEM_IFACE" ]]; then ip -o link show "$NETEM_IFACE" | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}'; else echo "NA"; fi)
force_disable_offload=$FORCE_DISABLE_OFFLOAD
effective_tso=$(if [[ "$USE_NETEM" == "1" && "$NETEM_IFACE" == "lo" ]] && command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="tcp-segmentation-offload:" {print $2; exit}'; else echo "NA"; fi)
effective_gso=$(if [[ "$USE_NETEM" == "1" && "$NETEM_IFACE" == "lo" ]] && command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="generic-segmentation-offload:" {print $2; exit}'; else echo "NA"; fi)
effective_gro=$(if [[ "$USE_NETEM" == "1" && "$NETEM_IFACE" == "lo" ]] && command -v ethtool >/dev/null 2>&1; then ethtool -k "$NETEM_IFACE" | awk '$1=="generic-receive-offload:" {print $2; exit}'; else echo "NA"; fi)
server_hostkey_mode=$SERVER_HOSTKEY_MODE
rounds=$ROUNDS
iterations_per_round=$ITERATIONS
warmup_per_round=$WARMUP
total_measurements=$((ROUNDS * ITERATIONS))
iterations=$ITERATIONS
warmup=$WARMUP
raw_csv=$RAW_CSV
summary_csv=$SUMMARY_CSV
manifest_csv=$MANIFEST_CSV
round_mean_csv=$ROUND_MEAN_CSV
EOF

echo "[OK] $PROFILE_TAG completed"
echo "[ARTIFACT] $SUMMARY_CSV"
