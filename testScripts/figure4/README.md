# Figure 4 — Migration Configurations across RTT Regimes

This experiment corresponds to **Figure 4** of the ICNP 2026 paper and
**Table IX** of the extended arXiv version.

It evaluates practical SSH post-quantum migration configurations under three
representative network-latency regimes. The transport key exchange and TCP
initial congestion window are fixed, while the client- and server-authentication
configurations are varied.

## Experimental Configuration

The published Figure 4 evaluation uses:

- Transport key exchange: `mlkem768x25519-sha256`
- TCP MSS: 1460 bytes
- TCP initial congestion window: 10 MSS
- Close RTT: approximately 37 ms
- Intermediate RTT: approximately 67 ms
- Long RTT: approximately 163 ms
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Reported metrics: mean, median (P50), and P95 handshake latency
- Published measurement count: 5,000 handshakes per configuration

Network delay and TCP parameters are configured using Linux `tc/netem`
and `ip route`.

The published evaluation was performed on Ubuntu 22.04.5 LTS with
GCC 11.4 using `-O2 -mavx2`, liboqs 0.15.0, and OpenSSL 3.0.2.

## Migration Configurations

Figure 4 evaluates eight client/server authentication configurations.

| Paper Notation | Client Authentication | Server Authentication |
| --- | --- | --- |
| `ed25519` | Ed25519 | Ed25519 |
| `h-md65` | ML-DSA-65 + Ed25519 | ML-DSA-65 + Ed25519 |
| `h-sd192f` | SLH-DSA-SHA2-192f + Ed25519 | SLH-DSA-SHA2-192f + Ed25519 |
| `h-mk768-md65` | ML-KEM-768 + Ed25519 | ML-DSA-65 + Ed25519 |
| `h-mk768-sd192f` | ML-KEM-768 + Ed25519 | SLH-DSA-SHA2-192f + Ed25519 |
| `ms-md65` | Ed25519 followed by ML-DSA-65 | ML-DSA-65 + Ed25519 |
| `ms-mk768` | Ed25519 followed by ML-KEM-768 | ML-DSA-65 + Ed25519 |
| `mk768-md65` | ML-KEM-768 | ML-DSA-65 |

The notation follows the paper:

- `h-` denotes a hybrid configuration that combines Ed25519 with the indicated
  post-quantum authenticator.
- `ms-` denotes SSH-native multi-step client authentication, where Ed25519 is
  followed by the indicated post-quantum user-authentication method.
- For labels of the form `X-Y`, `X` denotes client authentication and `Y`
  denotes server authentication.

For the hybrid configurations used in Figure 4, the runner explicitly invokes
the backend with:

```text
SERVER_HOSTKEY_MODE=and
```

This selects the combined classical/post-quantum authentication paths used by
the paper-aligned Figure 4 profiles, rather than the backend's alternative
`or` mode.

## RTT Profiles

The runner evaluates all eight configurations under three RTT profiles:

| Internal Result Tag | RTT | Paper Regime |
| --- | ---: | --- |
| `test2-C` | 37 ms | Close |
| `test2-I` | 67 ms | Intermediate |
| `test2-L` | 163 ms | Long |

The `test2-*` identifiers are retained internally for compatibility with the
original evaluation scripts. They all belong to the Figure 4 experiment.

## Running the Experiment

### Quick Reproduction Run

For practical validation, the runner uses a reduced sample count by default:

```bash
bash testScripts/figure4/run
```

The current default parameters are:

```text
ROUNDS=1
WARMUP=5
ITERATIONS=50
INITCWND_MSS=10
```

These defaults are intended to validate the build, authentication profiles,
network emulation, backend execution, and result-processing pipeline. They do
not provide the same statistical sample size as the published experiment.

### Paper-Scale Measurement Count

To use the measurement count reported in the paper:

```bash
env ROUNDS=1 ITERATIONS=5000 INITCWND_MSS=10 \
  bash testScripts/figure4/run
```

The paper specifies 5,000 measured handshakes per configuration. `WARMUP` is
an artifact-side option for unreported warm-up executions and is not part of
the published sample count.

Because the runner evaluates eight authentication configurations under three
RTT profiles, a paper-scale execution is substantially longer than the default
quick reproduction run.

Reproduced timing values may differ from the published measurements because of
hardware, CPU frequency, operating-system state, scheduling, and background
load.

## Output

New reproduction runs write their output under:

```text
testScripts/figure4/results/
```

The three RTT profiles use the following internal output directories:

```text
testScripts/figure4/results/test2-C/
testScripts/figure4/results/test2-I/
testScripts/figure4/results/test2-L/
```

The generated files include per-connection measurements, aggregated summaries,
and human-readable output produced by the backend and Figure 4 runner.

## Published Results

The numerical values reported in the extended paper are recorded in:

```text
testScripts/figure4/published_results.md
```

Those values are the canonical published results for Figure 4 / Table IX.
Locally generated files under `results/` correspond to a new reproduction run
and should not be confused with the published measurements.

## Operational Notes

- Root or `sudo` privileges are required for network emulation and TCP
  initial-window configuration.
- The Figure 4 runner explicitly uses `SERVER_HOSTKEY_MODE=and` for the
  paper-aligned hybrid authentication profiles.
- The experiment uses a dedicated test `sshd` instance and does not replace
  the system SSH daemon.
- Network settings modified during the experiment are restored by the cleanup
  logic on normal completion or interruption.
