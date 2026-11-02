#!/usr/bin/env bash
# Minimal end-to-end tests for draft-liu-sshm-kem-userauth-00.
# From the repository root: bash tests/integration/run.sh
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
WORK="$ROOT/tests/integration/.work"
PORT="${KEMUAUTH_TEST_PORT:-42222}"
TEST_USER="$(id -un)"
SERVER_PID=""
RUN_DIR=""

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            kill "$SERVER_PID" 2>/dev/null || true
        fi
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}
trap stop_server EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

show_logs() {
    local client_log="$1" server_log="$2"
    printf '\n--- Client log (last 35 lines) ---\n' >&2
    tail -n 35 "$client_log" >&2 || true
    printf '\n--- Server log (last 45 lines) ---\n' >&2
    tail -n 45 "$server_log" >&2 || true
    printf '\nComplete logs: %s\n' "$RUN_DIR" >&2
}

for tool in python3 timeout ss; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
for exe in ssh sshd sshd-session sshd-auth ssh-keygen; do
    [[ -x "$ROOT/$exe" ]] || fail "missing executable ./$exe; run: make ssh sshd sshd-session sshd-auth ssh-keygen"
done
[[ $(id -u) -ne 0 ]] || fail 'run this localhost test as an ordinary user, not root'
[[ "$PORT" =~ ^[0-9]+$ ]] || fail 'KEMUAUTH_TEST_PORT must be a decimal port number'
(( 10#$PORT >= 1024 && 10#$PORT <= 65535 )) || fail 'port must be between 1024 and 65535'
if ss -ltn | grep -Eq ":${PORT}[[:space:]]"; then
    fail "port $PORT is already in use; stop the earlier test sshd or choose KEMUAUTH_TEST_PORT"
fi

mkdir -p "$WORK"
chmod 700 "$WORK"
RUN_DIR="$(mktemp -d "$WORK/run.XXXXXXXX")"
chmod 700 "$RUN_DIR"
printf 'Logs: %s\n' "$RUN_DIR"

# Generate the three disposable test identities if they are missing.
for level in 512 768 1024; do
    identity="$WORK/id_mlkem${level}"
    if [[ ! -f "$identity" ]]; then
        bash tests/integration/generate_kem_identity.sh \
            "$identity" "ssh-mlkem-${level}-hmac-sha256"
    fi
done
# This also checks profile names, Base64 decoding, key lengths and permissions.
python3 tests/integration/prepare_test_keys.py

HOST_KEY="$WORK/ssh_host_ed25519_key"
if [[ ! -f "$HOST_KEY" ]]; then
    ./ssh-keygen -q -t ed25519 -N '' -f "$HOST_KEY"
fi
chmod 600 "$HOST_KEY"

# A fresh, unlisted ML-KEM-768 key is used for the rejection test.
UNAUTHORIZED_KEY="$RUN_DIR/id_unauthorized"
bash tests/integration/generate_kem_identity.sh \
    "$UNAUTHORIZED_KEY" ssh-mlkem-768-hmac-sha256

CONFIG="$RUN_DIR/sshd_config"
cat > "$CONFIG" <<EOF_CONFIG
Port $PORT
ListenAddress 127.0.0.1
AddressFamily inet
HostKey $HOST_KEY
HostKeyAlgorithms ssh-ed25519
PidFile $RUN_DIR/sshd.pid
SshdSessionPath $ROOT/sshd-session
SshdAuthPath $ROOT/sshd-auth
AllowUsers $TEST_USER
PermitRootLogin no
KEMAuthentication yes
KEMAuthAlgorithms ssh-mlkem-512-hmac-sha256,ssh-mlkem-768-hmac-sha256,ssh-mlkem-1024-hmac-sha256
AuthorizedKEMKeysFile $WORK/authorized_kem_keys
AuthenticationMethods publickey-kem
PubkeyAuthentication no
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes yes
PermitTTY no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 6
LoginGraceTime 60
LogLevel DEBUG3
EOF_CONFIG
chmod 600 "$CONFIG"
./sshd -t -f "$CONFIG" || fail 'sshd configuration check failed'

start_server() {
    local server_log="$1" config="${2:-$CONFIG}" attempt
    [[ -z "$SERVER_PID" ]] || fail 'internal error: previous test server still running'
    "$ROOT/sshd" -D -e -d -f "$config" > "$server_log" 2>&1 &
    SERVER_PID=$!
    for (( attempt = 0; attempt < 100; attempt++ )); do
        if grep -Fq "Server listening on 127.0.0.1 port $PORT." "$server_log"; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            tail -n 45 "$server_log" >&2 || true
            fail 'test sshd exited before listening'
        fi
        sleep 0.1
    done
    tail -n 45 "$server_log" >&2 || true
    fail 'test sshd did not reach listening state'
}

# Connect using ONLY publickey-kem and a single designated KEM identity.
ssh_client() {
    local level="$1" identity="$2" marker="$3" client_log="$4"
    timeout 35s "${KEMUAUTH_TEST_CLIENT_BIN:-$ROOT/ssh}" -v -F /dev/null \
        -o BatchMode=yes \
        -o ConnectionAttempts=1 \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$RUN_DIR/known_hosts" \
        -o GlobalKnownHostsFile=/dev/null \
        -o UpdateHostKeys=no \
        -o PreferredAuthentications=publickey-kem \
        -o PubkeyAuthentication=no \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o KEMAuthentication=yes \
        -o KEMAuthAlgorithms="ssh-mlkem-${level}-hmac-sha256" \
        -o IdentityKEMFile="$identity" \
        -p "$PORT" "$TEST_USER@127.0.0.1" \
        "echo $marker" > "$client_log" 2>&1
}

run_positive() {
    local level="$1" marker="KEMUAUTH_${1}_OK"
    local client_log="$RUN_DIR/client-${level}.log"
    local server_log="$RUN_DIR/server-${level}.log"
    printf 'Testing ML-KEM-%s login ...\n' "$level"
    start_server "$server_log"
    if ! ssh_client "$level" "$WORK/id_mlkem${level}" "$marker" "$client_log"; then
        show_logs "$client_log" "$server_log"
        fail "ML-KEM-$level SSH login failed"
    fi
    if ! grep -Fxq "$marker" "$client_log" ||
       ! grep -Fq 'using "publickey-kem"' "$client_log" ||
       ! grep -Fq "Accepted publickey-kem/ssh-mlkem-${level}-hmac-sha256" "$server_log"; then
        show_logs "$client_log" "$server_log"
        fail "ML-KEM-$level returned an unexpected authentication result"
    fi
    stop_server
    printf 'PASS: ML-KEM-%s end-to-end login\n' "$level"
}

for level in 512 768 1024; do
    run_positive "$level"
done

printf 'Testing unauthorized ML-KEM-768 identity rejection ...\n'
client_log="$RUN_DIR/client-unauthorized.log"
server_log="$RUN_DIR/server-unauthorized.log"
marker='KEMUAUTH_UNAUTHORIZED_SHOULD_NOT_RUN'
start_server "$server_log"
if ssh_client 768 "$UNAUTHORIZED_KEY" "$marker" "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'unauthorized identity was accepted'
else
    rejected_status=$?
fi
# OpenSSH returns 255 on authentication denial; 124 would mean timeout.
if [[ "$rejected_status" -ne 255 ]] ||
   ! grep -Fq 'Permission denied' "$client_log" ||
   grep -Fq 'using "publickey-kem"' "$client_log" ||
   grep -Fxq "$marker" "$client_log" ||
   grep -Fq 'Accepted publickey-kem/' "$server_log" ||
   ! grep -Fq 'method publickey-kem' "$server_log"; then
    show_logs "$client_log" "$server_log"
    fail 'unauthorized test did not reach the expected authentication rejection'
fi
stop_server
printf 'PASS: unauthorized ML-KEM-768 identity rejected\n'
# A valid, *authorized* public key paired with another key's private part
# decapsulates to the wrong shared secret. The client must not authenticate.
# This exercises the full Challenge/Response path without production test hooks.
MISMATCH_KEY="$RUN_DIR/id_mismatched_secret"
awk '$1 == "algorithm" || $1 == "public" { print }' \
    "$WORK/id_mlkem768" > "$MISMATCH_KEY"
awk '$1 == "secret" { print }' "$UNAUTHORIZED_KEY" >> "$MISMATCH_KEY"
chmod 600 "$MISMATCH_KEY"
[[ $(wc -l < "$MISMATCH_KEY") -eq 3 ]] || fail 'failed to construct mismatched-key identity'
printf 'Testing incorrect ML-KEM-768 confirmation ...\n'
client_log="$RUN_DIR/client-wrong-confirmation.log"
server_log="$RUN_DIR/server-wrong-confirmation.log"
start_server "$server_log"
if ssh_client 768 "$MISMATCH_KEY" KEMUAUTH_BAD_CONFIRM_SHOULD_NOT_RUN "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'mismatched-secret identity was accepted'
else
    rejected_status=$?
fi
# The current monitor logs failed KEM responses as "Failed unknown".
# Also accept an accurately attributed failure if the logging is fixed later.
if [[ "$rejected_status" -ne 255 ]] ||
   ! grep -Fq 'Permission denied' "$client_log" ||
   ! grep -Fq 'Postponed publickey-kem' "$server_log" ||
   ! grep -Eq '^Failed (publickey-kem|unknown) for ' "$server_log" ||
   grep -Fq 'Accepted publickey-kem/' "$server_log" ||
   grep -Fxq 'KEMUAUTH_BAD_CONFIRM_SHOULD_NOT_RUN' "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'wrong-confirmation test did not reach the expected rejection'
fi
stop_server
printf 'PASS: mismatched-secret ML-KEM-768 confirmation rejected\n'

# Create a separate conventional SSH user key for policy and fallback tests.
FALLBACK_KEY="$RUN_DIR/id_ed25519_fallback"
"$ROOT/ssh-keygen" -q -t ed25519 -N '' -f "$FALLBACK_KEY"
cp "$FALLBACK_KEY.pub" "$RUN_DIR/authorized_keys"
chmod 600 "$RUN_DIR/authorized_keys" "$FALLBACK_KEY"

# Even with ordinary publickey ENABLED and its key authorized, the
# AuthenticationMethods policy must require publickey-kem.
FORCE_CONFIG="$RUN_DIR/sshd_force_kem_config"
sed 's/^PubkeyAuthentication no$/PubkeyAuthentication yes/' \
    "$CONFIG" > "$FORCE_CONFIG"
printf 'AuthorizedKeysFile %s\n' "$RUN_DIR/authorized_keys" >> "$FORCE_CONFIG"
chmod 600 "$FORCE_CONFIG"
"$ROOT/sshd" -t -f "$FORCE_CONFIG" || fail 'forced-KEM sshd config check failed'
printf 'Testing forced-KEMUAuth policy (no publickey bypass) ...\n'
client_log="$RUN_DIR/client-force-kem.log"
server_log="$RUN_DIR/server-force-kem.log"
start_server "$server_log" "$FORCE_CONFIG"
if timeout 35s "$ROOT/ssh" -v -F /dev/null \
    -o BatchMode=yes \
    -o ConnectionAttempts=1 \
    -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$RUN_DIR/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UpdateHostKeys=no \
    -o PreferredAuthentications=publickey \
    -o KEMAuthentication=no \
    -o PubkeyAuthentication=yes \
    -o IdentitiesOnly=yes \
    -o IdentityAgent=none \
    -o IdentityFile="$FALLBACK_KEY" \
    -p "$PORT" "$TEST_USER@127.0.0.1" \
    'echo KEMUAUTH_POLICY_BYPASS' > "$client_log" 2>&1; then
    show_logs "$client_log" "$server_log"
    fail 'server policy was bypassed via ordinary publickey authentication'
else
    rejected_status=$?
fi
if [[ "$rejected_status" -ne 255 ]] ||
   ! grep -Fq 'Permission denied' "$client_log" ||
   grep -Fq 'Authenticated to ' "$client_log" ||
   grep -Fq 'Accepted publickey' "$server_log"; then
    show_logs "$client_log" "$server_log"
    fail 'forced-KEMUAuth policy did not reject conventional publickey'
fi
stop_server
printf 'PASS: forced KEMUAuth policy rejected conventional publickey\n'

# A second, explicitly permissive server configuration exercises fallback.
# AuthenticationMethods is intentionally omitted: the server may accept
# either publickey-kem or ordinary publickey.  The first, unauthorized KEM
# credential should fail, then an allowed Ed25519 credential should succeed.
FALLBACK_CONFIG="$RUN_DIR/sshd_fallback_config"
sed -e '/^AuthenticationMethods publickey-kem$/d' \
    -e 's/^PubkeyAuthentication no$/PubkeyAuthentication yes/' \
    "$CONFIG" > "$FALLBACK_CONFIG"
printf 'AuthorizedKeysFile %s\n' "$RUN_DIR/authorized_keys" >> "$FALLBACK_CONFIG"
chmod 600 "$FALLBACK_CONFIG"
"$ROOT/sshd" -t -f "$FALLBACK_CONFIG" || fail 'fallback sshd config check failed'
printf 'Testing explicitly permitted publickey fallback ...\n'
client_log="$RUN_DIR/client-fallback.log"
server_log="$RUN_DIR/server-fallback.log"
start_server "$server_log" "$FALLBACK_CONFIG"
if ! timeout 35s "$ROOT/ssh" -v -F /dev/null \
    -o BatchMode=yes \
    -o ConnectionAttempts=1 \
    -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$RUN_DIR/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null \
    -o UpdateHostKeys=no \
    -o PreferredAuthentications=publickey-kem,publickey \
    -o KEMAuthentication=yes \
    -o KEMAuthAlgorithms=ssh-mlkem-768-hmac-sha256 \
    -o IdentityKEMFile="$UNAUTHORIZED_KEY" \
    -o PubkeyAuthentication=yes \
    -o IdentitiesOnly=yes \
    -o IdentityAgent=none \
    -o IdentityFile="$FALLBACK_KEY" \
    -p "$PORT" "$TEST_USER@127.0.0.1" \
    'echo KEMUAUTH_FALLBACK_OK' > "$client_log" 2>&1; then
    show_logs "$client_log" "$server_log"
    fail 'permitted ordinary-publickey fallback failed'
fi
if ! grep -Fxq 'KEMUAUTH_FALLBACK_OK' "$client_log" ||
   ! grep -Fq 'using "publickey"' "$client_log" ||
   ! grep -Fq 'Next authentication method: publickey-kem' "$client_log" ||
   ! grep -Fq 'Accepted publickey for' "$server_log" ||
   grep -Fq 'Accepted publickey-kem/' "$server_log"; then
    show_logs "$client_log" "$server_log"
    fail 'fallback did not follow the expected KEM-to-publickey path'
fi
stop_server
printf 'PASS: explicitly permitted ordinary publickey fallback\n'

# Verify the monitor rechecks authorization after it created the challenge.
# A test-only LD_PRELOAD shim stops this test client at OQS_KEM_decaps.
# While the client waits, remove the authorized ML-KEM-768 key and then
# let it respond. This must fail; an early-only authorization check would
# incorrectly allow the completed authentication.
printf 'Testing authorization revoked after Challenge ...\n'
REVOCATION_AUTH="$RUN_DIR/authorized_kem_keys_revocation"
REVOCATION_CONFIG="$RUN_DIR/sshd_revocation_config"
cp "$WORK/authorized_kem_keys" "$REVOCATION_AUTH"
chmod 600 "$REVOCATION_AUTH"
sed "s@^AuthorizedKEMKeysFile .*@AuthorizedKEMKeysFile $REVOCATION_AUTH@" \
    "$CONFIG" > "$REVOCATION_CONFIG"
chmod 600 "$REVOCATION_CONFIG"
"$ROOT/sshd" -t -f "$REVOCATION_CONFIG" || fail 'revocation sshd config check failed'

command -v cc >/dev/null 2>&1 || fail 'C compiler required for revocation test'
REVOCATION_GATE="$RUN_DIR/pause_decaps.so"
cc -O2 -Wall -Wextra -fPIC -shared \
    -o "$REVOCATION_GATE" tests/integration/pause_decaps.c -ldl \
    || fail 'unable to build revocation synchronization helper'

client_log="$RUN_DIR/client-revocation.log"
server_log="$RUN_DIR/server-revocation.log"
ready_marker="$RUN_DIR/revocation-ready"
release_marker="$RUN_DIR/revocation-release"
marker='KEMUAUTH_REVOKED_SHOULD_NOT_RUN'
start_server "$server_log" "$REVOCATION_CONFIG"
(
    export LD_PRELOAD="$REVOCATION_GATE"
    export KEMUAUTH_TEST_READY="$ready_marker"
    export KEMUAUTH_TEST_RELEASE="$release_marker"
    ssh_client 768 "$WORK/id_mlkem768" "$marker" "$client_log"
) &
revocation_client_pid=$!

reached_decaps=0
for (( attempt = 0; attempt < 120; attempt++ )); do
    if [[ -f "$ready_marker" ]]; then
        reached_decaps=1
        break
    fi
    if ! kill -0 "$revocation_client_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$reached_decaps" -ne 1 ]]; then
    # Never strand an intercepted SSH process if the helper did not run.
    touch "$release_marker"
    wait "$revocation_client_pid" 2>/dev/null || true
    show_logs "$client_log" "$server_log"
    fail 'client did not reach the decapsulation gate; check dynamic liboqs linkage'
fi

# Atomically replace the server-side authorization file. Keep 512/1024
# entries, remove only 768, and do not modify the shared test fixture.
awk '$1 != "ssh-mlkem-768-hmac-sha256" { print }' \
    "$REVOCATION_AUTH" > "$REVOCATION_AUTH.next"
chmod 600 "$REVOCATION_AUTH.next"
[[ $(wc -l < "$REVOCATION_AUTH.next") -eq 2 ]] || fail 'unexpected revocation authorization contents'
mv "$REVOCATION_AUTH.next" "$REVOCATION_AUTH"
touch "$release_marker"

if wait "$revocation_client_pid"; then
    revoked_status=0
else
    revoked_status=$?
fi
if [[ "$revoked_status" -ne 255 ]] ||
   ! grep -Fq 'Permission denied' "$client_log" ||
   ! grep -Fq 'Postponed publickey-kem' "$server_log" ||
   ! grep -Eq '^Failed (publickey-kem|unknown) for ' "$server_log" ||
   grep -Fq 'Accepted publickey-kem/' "$server_log" ||
   grep -Fxq "$marker" "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'server did not reject authentication after revocation'
fi
stop_server
printf 'PASS: authorization revoked after Challenge was rejected\n'

# A test-only SSH client sends a NEW USERAUTH_REQUEST ("none") after
# receiving an actual KEM challenge instead of sending a KEM response.
# This exercises auth2_kem_stop() and the privileged Monitor Cancel RPC.
# Its temporary source/object/binary live only under the ignored .work/.
printf 'Testing Challenge cancellation by an intervening authentication request ...\n'
if ! make -s -f Makefile -f tests/integration/Makefile.cancel \
    KEMU_CANCEL_DIR="$RUN_DIR" kem-cancel-client > "$RUN_DIR/cancel-build.log" 2>&1; then
    cat "$RUN_DIR/cancel-build.log" >&2
    fail 'unable to build test-only Cancel client'
fi
cancel_client="$RUN_DIR/ssh-kem-cancel"
[[ -x "$cancel_client" ]] || fail 'Cancel test client was not built'
client_log="$RUN_DIR/client-cancel.log"
server_log="$RUN_DIR/server-cancel.log"
marker='KEMUAUTH_CANCEL_SHOULD_NOT_RUN'
start_server "$server_log"
if KEMUAUTH_TEST_CLIENT_BIN="$cancel_client" \
    KEMUAUTH_TEST_CANCEL_AFTER_CHALLENGE=1 \
    ssh_client 768 "$WORK/id_mlkem768" "$marker" "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'interrupted KEM authentication was accepted'
else
    cancel_status=$?
fi
if [[ "$cancel_status" -ne 255 ]] ||
   ! grep -Fq 'KEMUAUTH_CANCEL_TEST_REQUEST_SENT' "$client_log" ||
   ! grep -Fq 'Postponed publickey-kem' "$server_log" ||
   ! grep -Fq 'cancelling outstanding KEM challenge' "$server_log" ||
   ! grep -Fq 'Permission denied' "$client_log" ||
   grep -Fq 'Accepted publickey-kem/' "$server_log" ||
   grep -Fxq "$marker" "$client_log"; then
    show_logs "$client_log" "$server_log"
    fail 'Cancel was not observed or interrupted authentication was accepted'
fi
stop_server
printf 'PASS: pending Challenge cancelled on new authentication request\n'

printf '\nPASS: 9/9 integration and policy checks. Logs: %s\n' "$RUN_DIR"
