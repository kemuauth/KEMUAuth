
#include "includes.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"

struct ssh;
#include "ssh-kem.h"

/* Write test output as raw bytes for independent verification. */
static int
write_bytes(const char *path, const u_char *data, size_t len)
{
    FILE *f;
    int ok;

    if ((f = fopen(path, "wb")) == NULL)
        return -1;

    ok = fwrite(data, 1, len, f) == len;
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

    u_char pk[1184];
    u_char ct[1088];
    u_char sid[32];
    u_char secret[32];
    u_char ca[32];

    struct sshbuf *blob = NULL;
    struct sshbuf *mac_input = NULL;

    size_t i;
    int r, result = 1;

    /* Fixed synthetic inputs; no randomness is used. */
    for (i = 0; i < sizeof(pk); i++)
        pk[i] = (u_char)(i & 0xff);

    for (i = 0; i < sizeof(ct); i++)
        ct[i] = (u_char)((7 * i + 3) & 0xff);

    for (i = 0; i < sizeof(sid); i++)
        sid[i] = (u_char)(0x40 + i);

    for (i = 0; i < sizeof(secret); i++)
        secret[i] = (u_char)(0xa0 + i);

    /* Encode the SSH public key blob. */
    r = ssh_kem_encode_public_key_blob(
        alg, pk, sizeof(pk), &blob);

    if (r != 0) {
        fprintf(stderr, "FAIL: key blob encoding (%d)\n", r);
        goto out;
    }

    /* Construct the exact draft MAC_input. */
    r = ssh_kem_build_mac_input(
        sid, sizeof(sid),
        user, service, alg,
        sshbuf_ptr(blob), sshbuf_len(blob),
        ct, sizeof(ct),
        &mac_input);

    if (r != 0) {
        fprintf(stderr, "FAIL: MAC_input construction (%d)\n", r);
        goto out;
    }

    /* Compute the expected client confirmation value. */
    r = ssh_kem_compute_confirmation(
        sid, sizeof(sid),
        user, service, alg,
        sshbuf_ptr(blob), sshbuf_len(blob),
        ct, sizeof(ct),
        secret, sizeof(secret),
        ca, sizeof(ca));

    if (r != 0) {
        fprintf(stderr, "FAIL: confirmation computation (%d)\n", r);
        goto out;
    }

    /* Export the full intermediate data for comparison. */
    if (write_bytes("tests/protocol/kem_mac_input.bin",
        sshbuf_ptr(mac_input), sshbuf_len(mac_input)) != 0 ||
        write_bytes("tests/protocol/kem_ca.bin",
        ca, sizeof(ca)) != 0) {
        fprintf(stderr, "FAIL: writing test outputs\n");
        goto out;
    }

    printf("PASS: C confirmation computation\n");
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
