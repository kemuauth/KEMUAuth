
#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"

struct ssh;
#include "ssh-kem.h"

#define VDIR "tests/protocol/vector-work/"

#define CHECK(cond, msg) do {                         \
    if (!(cond)) {                                    \
        fprintf(stderr, "FAIL: %s\n", msg);            \
        goto out;                                     \
    }                                                 \
} while (0)

static int
read_exact(const char *name, u_char *buf, size_t len)
{
    FILE *f;
    int ok;

    if ((f = fopen(name, "rb")) == NULL)
        return -1;

    ok = fread(buf, 1, len, f) == len;
    if (ok)
        ok = fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0)
        ok = 0;

    return ok ? 0 : -1;
}

static int
write_exact(const char *name, const u_char *buf, size_t len)
{
    FILE *f;
    int ok;

    if ((f = fopen(name, "wb")) == NULL)
        return -1;

    ok = fwrite(buf, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = 0;

    return ok ? 0 : -1;
}

int
main(void)
{
    const char *alg = SSH_KEM_DEFAULT_ALG;
    const char *user = "alice";
    const char *service = "ssh-connection";

    u_char ek[1184], ct[1088];
    u_char secret[32], sid[32], ca[32] = {0};

    struct sshbuf *blob = NULL;
    struct sshbuf *mac_input = NULL;
    int r, result = 1;

    CHECK(read_exact(VDIR "ek.bin",
        ek, sizeof(ek)) == 0, "read ek");
    CHECK(read_exact(VDIR "ct.bin",
        ct, sizeof(ct)) == 0, "read ct");
    CHECK(read_exact(VDIR "K_C.bin",
        secret, sizeof(secret)) == 0, "read K_C");
    CHECK(read_exact(VDIR "sid.bin",
        sid, sizeof(sid)) == 0, "read sid");

    /* Validate the actual ML-KEM-768 public key. */
    CHECK(ssh_kem_validate_public_key(
        alg, ek, sizeof(ek)) == 0,
        "FIPS 203 public key validation");

    /* Encode the complete SSH public key blob. */
    r = ssh_kem_encode_public_key_blob(
        alg, ek, sizeof(ek), &blob);
    CHECK(r == 0, "public key blob encoding");
    CHECK(sshbuf_len(blob) == 1205, "blob length");

    /* Build the draft's exact MAC_input. */
    r = ssh_kem_build_mac_input(
        sid, sizeof(sid),
        user, service, alg,
        sshbuf_ptr(blob), sshbuf_len(blob),
        ct, sizeof(ct), &mac_input);
    CHECK(r == 0, "MAC_input construction");
    CHECK(sshbuf_len(mac_input) == 3680,
        "MAC_input length");

    /* Compute the actual confirmation value. */
    r = ssh_kem_compute_confirmation(
        sid, sizeof(sid),
        user, service, alg,
        sshbuf_ptr(blob), sshbuf_len(blob),
        ct, sizeof(ct),
        secret, sizeof(secret),
        ca, sizeof(ca));
    CHECK(r == 0, "confirmation computation");

    /* Save C outputs for independent comparison. */
    CHECK(write_exact(VDIR "mac_input_c.bin",
        sshbuf_ptr(mac_input),
        sshbuf_len(mac_input)) == 0,
        "write C MAC_input");

    CHECK(write_exact(VDIR "ca_c.bin",
        ca, sizeof(ca)) == 0,
        "write C confirmation");

    printf("PASS: C computation using real ML-KEM-768 data\n");
    printf("  Public key validation: PASS\n");
    printf("  Public key blob: %zu bytes\n", sshbuf_len(blob));
    printf("  MAC_input: %zu bytes\n", sshbuf_len(mac_input));
    printf("  Confirmation: %zu bytes\n", sizeof(ca));

    result = 0;

out:
    explicit_bzero(secret, sizeof(secret));
    explicit_bzero(ca, sizeof(ca));
    sshbuf_free(mac_input);
    sshbuf_free(blob);
    return result;
}
