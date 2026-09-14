/*
 * microbench_decaps.c — ML-KEM-768 local decapsulation timing microbenchmark
 *
 * Measures local execution time of OQS_KEM_decaps for each ciphertext class.
 *
 * Build:
 *   gcc -O2 -o microbench_decaps microbench_decaps.c \
 *       -I$(ROOT_DIR) -I$(LIBOQS_DIR)/include \
 *       -L$(LIBOQS_DIR)/lib -loqs -lcrypto -lm
 *
 * Or via pkg-config:
 *   gcc -O2 -o microbench_decaps microbench_decaps.c \
 *       $(pkg-config --cflags --libs liboqs) -lcrypto -lm
 *
 * Usage:
 *   ./microbench_decaps [warmup=10000] [iterations=50000]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* If liboqs is unavailable, compile with built-in stubs.
 * Comment out the line below to disable liboqs dependency (structure validation only). */
/* #define USE_LIBOQS */

#ifdef USE_LIBOQS
#include <oqs/oqs.h>
#endif

#define MLKEM768_PK_LEN  1184
#define MLKEM768_SK_LEN  2400
#define MLKEM768_CT_LEN  1088
#define MLKEM768_SS_LEN  32

/* ---- Timer ---- */
static inline uint64_t get_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ---- Malformed ciphertext generation ---- */
typedef struct {
  const char *name;
  uint8_t ct[MLKEM768_CT_LEN];
  size_t ct_len;
} CiphertextSample;

static void flip_bit(uint8_t *ct, size_t len, int bit_idx) {
  ct[bit_idx / 8] ^= (1U << (bit_idx % 8));
}

static void generate_samples(
    const uint8_t *valid_ct, size_t valid_len,
    CiphertextSample *samples, int *nsamples)
{
  int idx = 0;

  /* Valid */
  samples[idx].name = "valid";
  memcpy(samples[idx].ct, valid_ct, valid_len);
  samples[idx].ct_len = valid_len;
  idx++;

  /* One-bit flip */
  samples[idx].name = "onebit";
  memcpy(samples[idx].ct, valid_ct, valid_len);
  flip_bit(samples[idx].ct, valid_len, rand() % (valid_len * 8));
  samples[idx].ct_len = valid_len;
  idx++;

  /* Multi-bit flip (~1% bits) */
  samples[idx].name = "multibit";
  memcpy(samples[idx].ct, valid_ct, valid_len);
  int nflips = (valid_len * 8) / 100 + 1;
  for (int i = 0; i < nflips; i++)
    flip_bit(samples[idx].ct, valid_len, rand() % (valid_len * 8));
  samples[idx].ct_len = valid_len;
  idx++;

  /* Random */
  samples[idx].name = "random";
  for (size_t i = 0; i < valid_len; i++)
    samples[idx].ct[i] = (uint8_t)(rand() & 0xFF);
  samples[idx].ct_len = valid_len;
  idx++;

  /* All-zero */
  samples[idx].name = "allzero";
  memset(samples[idx].ct, 0, valid_len);
  samples[idx].ct_len = valid_len;
  idx++;

  /* All-ff */
  samples[idx].name = "allff";
  memset(samples[idx].ct, 0xFF, valid_len);
  samples[idx].ct_len = valid_len;
  idx++;

  *nsamples = idx;
}

/* ---- Bubble sort (for percentile calculation) ---- */
static void sort_doubles(double *arr, int n) {
  for (int i = 0; i < n - 1; i++)
    for (int j = 0; j < n - i - 1; j++)
      if (arr[j] > arr[j + 1]) {
        double tmp = arr[j];
        arr[j] = arr[j + 1];
        arr[j + 1] = tmp;
      }
}

static double percentile(double *sorted, int n, double pct) {
  if (n == 0) return 0.0;
  int idx = (int)(n * pct / 100.0);
  if (idx >= n) idx = n - 1;
  if (idx < 0) idx = 0;
  return sorted[idx];
}

static double mean(double *vals, int n) {
  if (n == 0) return 0.0;
  double sum = 0.0;
  for (int i = 0; i < n; i++) sum += vals[i];
  return sum / n;
}

/* ---- Main ---- */
int main(int argc, char **argv) {
  int warmup = (argc > 1) ? atoi(argv[1]) : 10000;
  int iterations = (argc > 2) ? atoi(argv[2]) : 50000;

  srand(42);

  printf("# Local ML-KEM-768 Decapsulation Microbenchmark\n");
  printf("# Warmup: %d  Iterations: %d\n", warmup, iterations);
  printf("# ML-KEM-768 CT_LEN=%d SS_LEN=%d\n\n", MLKEM768_CT_LEN, MLKEM768_SS_LEN);

#ifdef USE_LIBOQS
  /* Initialize OQS */
  OQS_init();

  /* Generate long-term keypair */
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
    return 1;
  }

  uint8_t pk[MLKEM768_PK_LEN];
  uint8_t sk[MLKEM768_SK_LEN];
  if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: keypair failed\n");
    OQS_KEM_free(kem);
    return 1;
  }

  /* Generate valid ciphertext */
  uint8_t valid_ct[MLKEM768_CT_LEN];
  uint8_t valid_ss[MLKEM768_SS_LEN];
  if (OQS_KEM_encaps(kem, valid_ct, valid_ss, pk) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: encaps failed\n");
    OQS_KEM_free(kem);
    return 1;
  }
#else
  /* Stub: validates script structure when liboqs is unavailable */
  printf("# WARNING: liboqs not available, generating dummy ciphertext\n");

  uint8_t pk[MLKEM768_PK_LEN];
  uint8_t sk[MLKEM768_SK_LEN];
  uint8_t valid_ct[MLKEM768_CT_LEN];
  uint8_t valid_ss[MLKEM768_SS_LEN];
  memset(pk, 0xAA, sizeof(pk));
  memset(sk, 0xBB, sizeof(sk));
  for (int i = 0; i < MLKEM768_CT_LEN; i++) valid_ct[i] = (uint8_t)(i & 0xFF);
#endif

  /* Generate malformed samples */
  CiphertextSample samples[8];
  int nsamples = 0;
  generate_samples(valid_ct, MLKEM768_CT_LEN, samples, &nsamples);

  printf("# Generated %d sample classes\n\n", nsamples);

  /* Warmup */
  printf("# Warming up (%d iterations)...\n", warmup);
  for (int w = 0; w < warmup; w++) {
    int si = w % nsamples;
#ifdef USE_LIBOQS
    uint8_t ss[MLKEM768_SS_LEN];
    OQS_KEM_decaps(kem, ss, samples[si].ct, sk);
#else
    volatile int dummy = 0;
    for (size_t b = 0; b < samples[si].ct_len; b++)
      dummy += samples[si].ct[b];
#endif
  }

  /* Measurement */
  printf("# Measuring (%d iterations per class)...\n", iterations);

  /* Allocate per-class storage */
  double *all_times[8];
  int counts[8];
  for (int s = 0; s < nsamples; s++) {
    all_times[s] = (double *)malloc(iterations * sizeof(double));
    counts[s] = 0;
  }

  /* Interleaved measurement */
  for (int i = 0; i < iterations * nsamples; i++) {
    int si = i % nsamples;

    uint64_t before = get_ns();

#ifdef USE_LIBOQS
    uint8_t ss[MLKEM768_SS_LEN];
    OQS_KEM_decaps(kem, ss, samples[si].ct, sk);
#else
    volatile int dummy = 0;
    for (size_t b = 0; b < samples[si].ct_len; b++)
      dummy += samples[si].ct[b];
    (void)dummy;
#endif

    uint64_t after = get_ns();
    uint64_t elapsed = after - before;

    all_times[si][counts[si]++] = (double)elapsed;
  }

  /* Output results */
  printf("\n");
  printf("| Ciphertext Class | Samples | Mean (ns) | Median (ns) | "
         "p5 (ns) | p95 (ns) | Rel. Median Diff (%%) | Obvious Separation? |\n");
  printf("|:---|---:|---:|---:|---:|---:|---:|:---:|\n");

  double valid_median = 0.0;
  /* Find valid median first */
  for (int s = 0; s < nsamples; s++) {
    if (strcmp(samples[s].name, "valid") == 0) {
      sort_doubles(all_times[s], counts[s]);
      valid_median = percentile(all_times[s], counts[s], 50.0);
      break;
    }
  }

  for (int s = 0; s < nsamples; s++) {
    sort_doubles(all_times[s], counts[s]);

    double mean_ns = mean(all_times[s], counts[s]);
    double med_ns = percentile(all_times[s], counts[s], 50.0);
    double p5_ns = percentile(all_times[s], counts[s], 5.0);
    double p95_ns = percentile(all_times[s], counts[s], 95.0);

    double rel_diff = 0.0;
    if (valid_median > 0.0) {
      rel_diff = (med_ns - valid_median) / valid_median * 100.0;
    }

    const char *sep = "—";
    if (rel_diff > 50.0 || rel_diff < -50.0)
      sep = "LIKELY";

    printf("| %-16s | %d | %.1f | %.1f | %.1f | %.1f | %+.2f | %s |\n",
           samples[s].name, counts[s],
           mean_ns, med_ns, p5_ns, p95_ns,
           rel_diff, sep);

    free(all_times[s]);
  }

#ifdef USE_LIBOQS
  OQS_KEM_free(kem);
  OQS_destroy();
#endif

  return 0;
}
