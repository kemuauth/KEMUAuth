# Figure 3 — Client-Authentication Algorithm Comparison

This experiment corresponds to **Figure 3** of the ICNP 2026 paper and
**Table VIII** of the extended arXiv version.

It evaluates end-to-end SSH handshake latency while varying only the
client-authentication algorithm. The transport key exchange, server
authentication, network delay, and TCP initial congestion window are kept
fixed.

## Experimental Configuration

The published Figure 3 evaluation uses:

- Transport key exchange: `mlkem768x25519-sha256`
- Server authentication: Ed25519
- RTT: approximately 67 ms
- TCP MSS: 1460 bytes
- TCP initial congestion window: 10 MSS
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Reported metrics: mean, median (P50), and P95 handshake latency
- Published measurement count: 5,000 handshakes per configuration

Network delay and TCP parameters are configured using Linux `tc/netem`
and `ip route`.

The published evaluation was performed on Ubuntu 22.04.5 LTS with
GCC 11.4, using `-O2 -mavx2`, liboqs 0.15.0, and OpenSSL 3.0.2.

## Client-Authentication Configurations

Figure 3 evaluates the following 13 client-authentication configurations:

| Authentication Method | Algorithm | Script Notation |
| --- | --- | --- |
| `publickey` | Ed25519 | `ed25519` |
| `publickey` | ML-DSA-44 | `md44` |
| `publickey` | ML-DSA-65 | `md65` |
| `publickey` | ML-DSA-87 | `md87` |
| `publickey` | Falcon-512 | `falcon512` |
| `publickey` | Falcon-1024 | `falcon1024` |
| `publickey` | SLH-DSA-SHA2-128f | `sd128f` |
| `publickey` | SLH-DSA-SHA2-192f | `sd192f` |
| `publickey` | SLH-DSA-SHA2-256f | `sd256f` |
| `publickey-kem` | ML-KEM-512 | `mk512` |
| `publickey-kem` | ML-KEM-768 | `mk768` |
| `publickey-kem` | ML-KEM-1024 | `mk1024` |
| `password` | Password (yescrypt) | `password` |

The password configuration is included as a deployment baseline. It does not
provide the registered public-key credential model or public-key
proof-of-possession property provided by `publickey` and `publickey-kem`.

## Running the Experiment

### Quick Reproduction Run

For practical validation, the script uses a reduced sample count by default:

```bash
sudo bash testScripts/figure3/run
```

The current default parameters are:

```text
ITERATIONS=200
WARMUP=5
RTT_MS=67
INITCWND_MSS=10
```

The reduced default is intended to validate the build, authentication
configurations, network setup, and result-processing pipeline. It does not
provide the same statistical sample size as the published experiment.

For a very short functional check:

```bash
sudo env ITERATIONS=5 WARMUP=1 \
  bash testScripts/figure3/run
```

### Paper-Scale Measurement Count

To use the measurement count reported in the paper:

```bash
sudo env ITERATIONS=5000 RTT_MS=67 INITCWND_MSS=10 \
  bash testScripts/figure3/run
```

The paper specifies 5,000 measured handshakes per configuration. `WARMUP` is
an artifact-side option for unreported warm-up rounds and is not part of the
published sample count.

Reproduced timing values may differ from the published values because of
hardware, CPU frequency, operating-system state, and background load.

## Interleaved Measurement Order

Measurements are collected in interleaved rounds. Within each round, the
algorithm order is shuffled and each authentication configuration is exercised
once.

This reduces systematic bias caused by slow environmental drift, such as CPU
temperature, frequency variation, or background system activity.

## Output

New reproduction runs write their output under:

```text
testScripts/figure3/results/
```

The principal output files are:

- `raw_runs.csv` — per-connection measurements
- `summary.csv` — aggregate mean/P50/P95 and failure information
- `readable.md` — human-readable summary
- `metadata.txt` — experiment and environment metadata

## Published Results

The numerical values reported in the paper are recorded in:

```text
testScripts/figure3/published_results.md
```

Those values are the canonical published results for Figure 3 / Table VIII.
Files generated under `results/` correspond to a new local reproduction run
and should not be confused with the published measurements.

## Operational Notes

- Root privileges are required for test-account management and network
  emulation.
- The test account defaults to `ssh_fig3_test`.
- The experiment uses a dedicated test `sshd` instance and does not replace
  the system SSH daemon.
- Network and interface settings modified during the experiment are restored
  by the cleanup handler on normal completion or interruption.
