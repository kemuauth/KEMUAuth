
#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Deterministic ML-KEM-768 test data generator.
 * Test-only seeds: never use these for real credentials.
 */

static int
save_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    int ok;

    if (f == NULL)
        return -1;

    ok = fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = 0;

    return ok ? 0 : -1;
}

#define SAVE(name, ptr, len) do {                              \
    if (save_file("tests/protocol/vector-work/" name ".bin",   \
        ptr, len) != 0) {                                      \
        fprintf(stderr, "FAIL: writing %s\n", name);          \
        goto out;                                             \
    }                                                         \
} while (0)

int
main(void)
{
    OQS_KEM *kem = NULL;
    uint8_t key_seed[64];
    uint8_t m[32];
    uint8_t sid[32];
    uint8_t recovered[32];

    uint8_t *ek = NULL;
    uint8_t *dk = NULL;
    uint8_t *ct = NULL;
    uint8_t *shared_secret = NULL;

    size_t i;
    int result = 1;

    /*
     * Fixed FIPS 203 inputs:
     * d = 00 01 ... 1f
     * z = 20 21 ... 3f
     * m = 40 41 ... 5f
     * sid = 60 61 ... 7f
     */
    for (i = 0; i < 64; i++)
        key_seed[i] = (uint8_t)i;

    for (i = 0; i < 32; i++) {
        m[i] = (uint8_t)(0x40 + i);
        sid[i] = (uint8_t)(0x60 + i);
    }

    OQS_init();

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "FAIL: ML-KEM-768 unavailable\n");
        goto out;
    }

    /* Verify all required FIPS 203 dimensions. */
    if (kem->length_public_key != 1184 ||
        kem->length_secret_key != 2400 ||
        kem->length_ciphertext != 1088 ||
        kem->length_shared_secret != 32 ||
        kem->length_keypair_seed != 64 ||
        kem->length_encaps_seed != 32) {
        fprintf(stderr, "FAIL: unexpected ML-KEM parameters\n");
        goto out;
    }

    ek = malloc(kem->length_public_key);
    dk = malloc(kem->length_secret_key);
    ct = malloc(kem->length_ciphertext);
    shared_secret = malloc(kem->length_shared_secret);

    if (ek == NULL || dk == NULL ||
        ct == NULL || shared_secret == NULL) {
        fprintf(stderr, "FAIL: memory allocation\n");
        goto out;
    }

    /* FIPS 203 ML-KEM.KeyGen_internal(d, z). */
    if (OQS_KEM_keypair_derand(
        kem, ek, dk, key_seed) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: deterministic key generation\n");
        goto out;
    }

    /* FIPS 203 ML-KEM.Encaps_internal(ek, m). */
    if (OQS_KEM_encaps_derand(
        kem, ct, shared_secret, ek, m) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: deterministic encapsulation\n");
        goto out;
    }

    /* Recover the shared secret through decapsulation. */
    if (OQS_KEM_decaps(
        kem, recovered, ct, dk) != OQS_SUCCESS) {
        fprintf(stderr, "FAIL: decapsulation\n");
        goto out;
    }

    if (memcmp(recovered, shared_secret, 32) != 0) {
        fprintf(stderr, "FAIL: shared secrets differ\n");
        goto out;
    }

    /* Export public deterministic vector inputs and outputs. */
    SAVE("d", key_seed, 32);
    SAVE("z", key_seed + 32, 32);
    SAVE("m", m, 32);
    SAVE("sid", sid, 32);
    SAVE("ek", ek, kem->length_public_key);
    SAVE("ct", ct, kem->length_ciphertext);
    SAVE("K_C", shared_secret, 32);

    printf("PASS: deterministic ML-KEM-768 generation\n");
    printf("  Encapsulation key: 1184 bytes\n");
    printf("  Ciphertext: 1088 bytes\n");
    printf("  Shared secret: 32 bytes\n");
    printf("  Encaps / Decaps consistency: PASS\n");
    printf("  Vector files written successfully\n");

    result = 0;

out:
    if (dk != NULL && kem != NULL)
        OQS_MEM_secure_free(dk, kem->length_secret_key);
    if (shared_secret != NULL)
        OQS_MEM_secure_free(shared_secret, 32);

    free(ek);
    free(ct);
    OQS_KEM_free(kem);
    OQS_destroy();

    return result;
}
