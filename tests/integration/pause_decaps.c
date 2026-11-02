/*
 * Integration-test-only synchronization gate for ML-KEM decapsulation.
 * Built as a shared object and preloaded only in the local SSH test client.
 * Never use this helper with a production SSH client.
 *
 * This function has the same C ABI as OQS_KEM_decaps(); the opaque
 * OQS_KEM pointer requires no knowledge of the liboqs structure layout.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef int (*oqs_decaps_fn)(const void *, uint8_t *,
    const uint8_t *, const uint8_t *);

int
OQS_KEM_decaps(const void *kem, uint8_t *shared_secret,
    const uint8_t *ciphertext, const uint8_t *secret_key)
{
    oqs_decaps_fn real_decaps;
    const char *ready = getenv("KEMUAUTH_TEST_READY");
    const char *release = getenv("KEMUAUTH_TEST_RELEASE");
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 50000000L };
    int fd, i;

    real_decaps = (oqs_decaps_fn)dlsym(RTLD_NEXT, "OQS_KEM_decaps");
    if (real_decaps == NULL) {
        fputs("KEMUAuth test gate: cannot resolve OQS_KEM_decaps\n", stderr);
        return -1;
    }
    if (ready != NULL && release != NULL) {
        fd = open(ready, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) {
            perror("KEMUAuth test gate: create ready marker");
            return -1;
        }
        if (close(fd) != 0)
            return -1;
        /* At most 20 seconds; never block a test client indefinitely. */
        for (i = 0; i < 400; i++) {
            if (access(release, F_OK) == 0)
                break;
            if (nanosleep(&delay, NULL) != 0 && errno != EINTR)
                return -1;
        }
        if (i == 400) {
            fputs("KEMUAuth test gate: timed out waiting for release\n", stderr);
            return -1;
        }
    }
    return real_decaps(kem, shared_secret, ciphertext, secret_key);
}
