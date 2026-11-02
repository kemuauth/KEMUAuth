
#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"

struct ssh;
#include "ssh-kem.h"

#define REQUIRE(cond, message) do {                       \
    if (!(cond)) {                                        \
        fprintf(stderr, "FAIL: %s\n", message);            \
        goto out;                                         \
    }                                                    \
} while (0)

int
main(void)
{
    const char *alg = SSH_KEM_DEFAULT_ALG;
    const char *format = SSH_KEM_KEY_FORMAT_MLKEM768;
    struct sshkem *kem = NULL;
    struct sshbuf *blob = NULL, *invalid_blob = NULL;
    u_char *pk = NULL, *sk = NULL;
    u_char *decoded = NULL, *mutated = NULL;
    const u_char *wire;
    size_t pk_len = 0, sk_len = 0;
    size_t blob_len, decoded_len = 0;
    size_t format_len = strlen(format);
    int result = 1;

    /* Generate a valid ML-KEM-768 key pair. */
    REQUIRE((kem = ssh_kem_new(alg)) != NULL,
        "ML-KEM-768 initialization");

    pk_len = ssh_kem_public_key_len(kem);
    sk_len = ssh_kem_secret_key_len(kem);

    REQUIRE(pk_len == 1184, "ML-KEM-768 public key length");

    pk = malloc(pk_len);
    sk = malloc(sk_len);
    REQUIRE(pk != NULL && sk != NULL, "key allocation");

    REQUIRE(ssh_kem_keypair(kem, pk, sk) == 0,
        "ML-KEM-768 key generation");

    REQUIRE(ssh_kem_validate_public_key(alg, pk, pk_len) == 0,
        "valid ML-KEM-768 encapsulation key");

    REQUIRE(ssh_kem_validate_public_key(alg, pk, pk_len - 1) != 0,
        "reject incorrect encapsulation key length");

    /* Encode the public key blob. */
    REQUIRE(ssh_kem_encode_public_key_blob(
        alg, pk, pk_len, &blob) == 0,
        "public key blob encoding");

    blob_len = sshbuf_len(blob);
    wire = sshbuf_ptr(blob);

    REQUIRE(blob_len == 8 + format_len + pk_len,
        "encoded blob length");

    /* Check the SSH binary encoding independently. */
    REQUIRE(wire[0] == 0 && wire[1] == 0 &&
        wire[2] == 0 && wire[3] == format_len,
        "format string length prefix");

    REQUIRE(memcmp(wire + 4, format, format_len) == 0,
        "public key format identifier");

    REQUIRE(wire[17] == 0 && wire[18] == 0 &&
        wire[19] == 4 && wire[20] == 160,
        "1184-byte key length prefix");

    REQUIRE(memcmp(wire + 21, pk, pk_len) == 0,
        "encoded public key bytes");

    /* Decode and compare the recovered public key. */
    REQUIRE(ssh_kem_decode_public_key_blob(
        alg, wire, blob_len, &decoded, &decoded_len) == 0,
        "public key blob decoding");

    REQUIRE(decoded_len == pk_len &&
        memcmp(decoded, pk, pk_len) == 0,
        "public key round trip");

    free(decoded);
    decoded = NULL;

    /* Check that invalid encodings are rejected. */
    mutated = malloc(blob_len + 1);
    REQUIRE(mutated != NULL, "mutation buffer allocation");

    memcpy(mutated, wire, blob_len);
    mutated[4] = 'S';

    REQUIRE(ssh_kem_decode_public_key_blob(
        alg, mutated, blob_len, &decoded, &decoded_len) != 0,
        "reject incorrect public key format");

    REQUIRE(ssh_kem_decode_public_key_blob(
        SSH_KEM_ALG_MLKEM512, wire, blob_len,
        &decoded, &decoded_len) != 0,
        "reject mismatched authentication profile");

    REQUIRE(ssh_kem_decode_public_key_blob(
        alg, wire, blob_len - 1,
        &decoded, &decoded_len) != 0,
        "reject truncated blob");

    memcpy(mutated, wire, blob_len);
    mutated[blob_len] = 0;

    REQUIRE(ssh_kem_decode_public_key_blob(
        alg, mutated, blob_len + 1,
        &decoded, &decoded_len) != 0,
        "reject trailing bytes");

    REQUIRE(ssh_kem_encode_public_key_blob(
        alg, pk, pk_len - 1, &invalid_blob) != 0,
        "reject incorrect raw public key length");

    /*
    * Corrupt the first 12-bit coefficient to 4095.
    * The structural length remains valid, but the key
    * must fail the FIPS 203 modulus check.
    *
    * No further use of the original public key follows.
    */
    pk[0] = 0xff;
    pk[1] = (pk[1] & 0xf0) | 0x0f;

    REQUIRE(ssh_kem_validate_public_key(alg, pk, pk_len) != 0,
        "reject non-canonical ML-KEM public key");

    printf("PASS: ML-KEM-768 public key blob tests\n");
    printf("  Raw key: %zu bytes\n", pk_len);
    printf("  Encoded blob: %zu bytes\n", blob_len);
    printf("  Round trip: PASS\n");
    printf("  Invalid input rejection: PASS\n");

    result = 0;

out:
    free(decoded);
    free(mutated);
    free(pk);
    if (sk != NULL) {
        explicit_bzero(sk, sk_len);
        free(sk);
    }
    sshbuf_free(invalid_blob);
    sshbuf_free(blob);
    ssh_kem_free(kem);
    return result;
}
