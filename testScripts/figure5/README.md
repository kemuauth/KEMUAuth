# Figure 5 — TCP Initial-Window Sensitivity

This experiment corresponds to **Figure 5** of the ICNP 2026 paper and
**Table X** of the extended arXiv version.

It studies how the TCP initial congestion window affects end-to-end SSH
handshake latency for authentication configurations with different
authentication-object sizes.

The transport key exchange and RTT are fixed while the TCP initial congestion
window is varied.

## Experimental Configuration

The published Figure 5 evaluation uses:

- Transport key exchange: `mlkem768x25519-sha256`
- RTT: approximately 67 ms
- TCP MSS: 1460 bytes
- TCP initial congestion windows:
  `3, 5, 7, 10, 15, 20, 25, 30, 35, 40, 50` MSS
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Reported latency statistics: P5, P50, and P95
- Published measurement count: 5,000 handshakes per configuration

Network delay and TCP parameters are configured using Linux `tc/netem`
and `ip route`.

The published evaluation was performed on Ubuntu 22.04.5 LTS with
GCC 11.4 using `-O2 -mavx2`, liboqs 0.15.0, and OpenSSL 3.0.2.

## Authentication Configurations

Figure 5 evaluates five client/server authentication configurations.

| Case | Client Authentication | Server Authentication | Paper Notation |
| --- | --- | --- | --- |
| A | Ed25519 | Ed25519 | `ed25519 + ed25519` |
| B | ML-DSA-65 | ML-DSA-65 | `md65 + md65` |
| C | SLH-DSA-SHA2-192f | SLH-DSA-SHA2-192f | `sd192f + sd192f` |
| D | ML-KEM-768 | ML-DSA-65 | `mk768 + md65` |
| E | ML-KEM-768 | SLH-DSA-SHA2-192f | `mk768 + sd192f` |

In the Figure 5 notation, `X + Y` denotes client authentication with `X`
and server authentication with `Y`.

The experiment is designed to expose transmission effects caused by
authentication-object size. Configurations involving large post-quantum
signatures are more sensitive to constrained initial TCP windows, whereas
compact configurations are comparatively stable.

## Running the Experiment

### Quick Reproduction Run

For practical validation, the runner uses a reduced sample count by default:

```bash
bash testScripts/figure5/run
```

The current default parameters are:

```text
RTT_MS=67
ROUNDS=1
WARMUP=5
ITERATIONS=50
INITCWND_LIST="3 5 7 10 15 20 25 30 35 40 50"
```

These defaults are intended to validate the build, authentication
configurations, TCP-window setup, backend execution, and result-processing
pipeline. They do not provide the same statistical sample size as the
published experiment.

### Paper-Scale Measurement Count

To use the measurement count reported in the paper:

```bash
env ROUNDS=1 ITERATIONS=5000 RTT_MS=67 \
  bash testScripts/figure5/run
```

The paper specifies 5,000 measured handshakes per configuration. `WARMUP` is
an artifact-side option for unreported warm-up executions and is not part of
the published sample count.

Because Figure 5 evaluates five authentication configurations across eleven
initial-window sizes, a paper-scale execution is substantially longer than the
default quick reproduction run.

Reproduced timing values may differ from the published measurements because
of hardware, CPU frequency, operating-system state, scheduling, and background
load.

## Output

New reproduction runs write their output under:

```text
testScripts/figure5/results/test3/
```

The principal normalized output files are:

- `raw_runs.csv` — per-connection measurements
- `round_means_append.csv` — per-round mean measurements
- `summary.csv` — mean/P50/P95 diagnostic summary
- `window_p5_p50_p95.csv` — P5/P50/P95 values for each window and case
- `readable.md` — paper-aligned human-readable P5/P50/P95 summary

The internal `test3` result identifier is retained for compatibility with the
original evaluation scripts. It refers to the Figure 5 experiment.

## Published Results

The numerical values reported in the extended paper are recorded in:

```text
testScripts/figure5/published_results.md
```

Those values are the canonical published results for Figure 5 / Table X.
Locally generated files under `results/` correspond to a new reproduction run
and should not be confused with the published measurements.

## Operational Notes

- Root or `sudo` privileges are required for network emulation and TCP
  initial-window configuration.
- The experiment uses a dedicated test `sshd` instance and does not replace
  the system SSH daemon.
- Network settings modified during the experiment are restored by the cleanup
  logic on normal completion or interruption.
