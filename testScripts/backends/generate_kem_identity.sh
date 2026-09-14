#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-$HOME/.ssh/id_mlkem768}"
KEM_ALG="${2:-ML-KEM-768}"
OUT_DIR="$(dirname "$OUT_FILE")"
TMP_DIR="$(mktemp -d)"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OQS_PREFIX="${OQS_PREFIX:-$ROOT_DIR/oqs}"

if [[ ! -f "$OQS_PREFIX/include/oqs/oqs.h" ]]; then
    echo "[ERR] liboqs headers not found under: $OQS_PREFIX"
    echo "[HINT] Build the repository-local liboqs first with:"
    echo "       LIBOQS_BRANCH=0.15.0 bash oqs-scripts/clone_liboqs.sh"
    echo "       bash oqs-scripts/build_liboqs.sh"
    exit 1
fi

if [[ ! -e "$OQS_PREFIX/lib/liboqs.so" ]]; then
    echo "[ERR] liboqs shared library not found under: $OQS_PREFIX/lib"
    echo "[HINT] Build the repository-local liboqs first with:"
    echo "       bash oqs-scripts/build_liboqs.sh"
    exit 1
fi

trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$OUT_DIR"

cat > "$TMP_DIR/gen_mlkem.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main(int argc, char **argv) {
    OQS_KEM *kem = NULL;
    uint8_t *pk = NULL, *sk = NULL;
    FILE *fpk = NULL, *fsk = NULL;
    const char *alg = NULL;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <pk.bin> <sk.bin> <alg>\\n", argv[0]);
        return 2;
    }
    alg = argv[3];
    if (strcasecmp(alg, "ML-KEM-512") == 0 || strcasecmp(alg, "mlkem512") == 0 ||
        strcasecmp(alg, "Kyber512") == 0 || strcasecmp(alg, "kyber512") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    } else if (strcasecmp(alg, "ML-KEM-768") == 0 || strcasecmp(alg, "mlkem768") == 0 ||
               strcasecmp(alg, "Kyber768") == 0 || strcasecmp(alg, "kyber768") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    } else if (strcasecmp(alg, "ML-KEM-1024") == 0 || strcasecmp(alg, "mlkem1024") == 0 ||
               strcasecmp(alg, "Kyber1024") == 0 || strcasecmp(alg, "kyber1024") == 0) {
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    } else {
        fprintf(stderr, "unsupported alg: %s\\n", alg);
        return 2;
    }
    if (kem == NULL) {
        fprintf(stderr, "OQS_KEM_new failed\\n");
        return 1;
    }
    pk = calloc(kem->length_public_key, 1);
    sk = calloc(kem->length_secret_key, 1);
    if (pk == NULL || sk == NULL) {
        fprintf(stderr, "calloc failed\\n");
        OQS_KEM_free(kem);
        free(pk);
        free(sk);
        return 1;
    }
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "OQS_KEM_keypair failed\\n");
        OQS_KEM_free(kem);
        free(pk);
        free(sk);
        return 1;
    }

    fpk = fopen(argv[1], "wb");
    fsk = fopen(argv[2], "wb");
    if (fpk == NULL || fsk == NULL) {
        fprintf(stderr, "fopen failed\\n");
        if (fpk) fclose(fpk);
        if (fsk) fclose(fsk);
        OQS_KEM_free(kem);
        free(pk);
        free(sk);
        return 1;
    }

    if (fwrite(pk, 1, kem->length_public_key, fpk) != kem->length_public_key ||
        fwrite(sk, 1, kem->length_secret_key, fsk) != kem->length_secret_key) {
        fprintf(stderr, "fwrite failed\\n");
        fclose(fpk);
        fclose(fsk);
        OQS_KEM_free(kem);
        free(pk);
        free(sk);
        return 1;
    }

    fclose(fpk);
    fclose(fsk);
    OQS_KEM_free(kem);
    free(pk);
    free(sk);
    return 0;
}
EOF

cc -O2 \
    -I"$OQS_PREFIX/include" \
    "$TMP_DIR/gen_mlkem.c" \
    -L"$OQS_PREFIX/lib" \
    -Wl,-rpath,"$OQS_PREFIX/lib" \
    -loqs \
    -o "$TMP_DIR/gen_mlkem"
"$TMP_DIR/gen_mlkem" "$TMP_DIR/pk.bin" "$TMP_DIR/sk.bin" "$KEM_ALG"

PUB_B64="$(base64 -w0 "$TMP_DIR/pk.bin")"
SEC_B64="$(base64 -w0 "$TMP_DIR/sk.bin")"

cat > "$OUT_FILE" <<EOF
algorithm $KEM_ALG
public $PUB_B64
secret $SEC_B64
EOF

chmod 600 "$OUT_FILE"
echo "[OK] generated: $OUT_FILE ($KEM_ALG)"
