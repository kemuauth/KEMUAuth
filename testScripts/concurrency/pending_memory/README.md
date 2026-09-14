# Pending Authentication State Memory Evaluation

This experiment evaluates the server-memory impact of simultaneously pending
KEMUAuth authentication challenges and compares it with an ML-DSA-65
public-key authentication baseline.

It corresponds to the pending-authentication-state evaluation reported in the
extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

The experiment is separate from the ordinary concurrent-throughput evaluation.
Its purpose is to hold multiple authentication attempts at the corresponding
authentication stage long enough to measure server memory as the number of
simultaneously pending connections increases.

## Experimental Method

For KEMUAuth, the client pauses after receiving the KEM challenge and before
decapsulation and response transmission. During this interval, the server
retains the pending KEMUAuth challenge state.

For the ML-DSA-65 baseline, the client pauses after receiving `PK_OK` and before
generating and sending the signature. This places the baseline connection at
the corresponding public-key authentication stage.

Both modes use barrier-synchronized client launch so that many connections
enter the pending or paused state at approximately the same time.

The experiment records the **actually observed** simultaneous pending or paused
connection count for every run. This is important because the observed maximum
may be lower than the requested target concurrency.

The published analysis therefore does not directly compare raw memory values
from unmatched target-concurrency runs. Instead, KEMUAuth and ML-DSA-65 are
fitted independently:

```text
M_KEMUAuth(P) = alpha_K + beta_K * P
M_ML-DSA(P)   = alpha_S + beta_S * P
```

where `P` is the observed simultaneous pending or paused connection count.

The two fitted models are then evaluated at common normalized values of `P`.

## Published Configuration and Results

The stored published run used:

```text
Runs per target configuration: 5
KEMUAuth response delay:       20000 ms
Hold window:                   35 s
Transport KEX:                 mlkem768x25519-sha256
Server host key:               ssh-mldsa-65
Memory accounting:             cgroup v2
```

The experiment runner supports target concurrency values such as:

```text
0 16 32 64 128 256
```

These are requested client counts, not guaranteed observed pending counts.

The largest normalized pending count reported in the paper is `P = 172`.
The published table uses:

```text
P = 16, 32, 64, 128, 172
```

because the final comparison is based on the independently fitted models rather
than on the requested target concurrency alone.

Published numerical results are preserved in:

```text
testScripts/concurrency/pending_memory/published_results.md
```

## Running the Experiment

The current runner defaults to:

```text
TARGET_CONCURRENCY = 0 16 32 64 128 256
RUNS               = 5
RESPONSE_DELAY_MS  = 10000
HOLD_WINDOW_SEC    = 15
SAMPLE_INTERVAL_SEC = 0.1
```

These defaults are suitable for reproducing the experimental pipeline.

Run with:

```bash
sudo bash testScripts/concurrency/pending_memory/run
```

To use the timing parameters associated with the stored published run:

```bash
sudo env \
  TARGET_CONCURRENCY="0 16 32 64 128 256" \
  RUNS=5 \
  RESPONSE_DELAY_MS=20000 \
  HOLD_WINDOW_SEC=35 \
  bash testScripts/concurrency/pending_memory/run
```

A shorter functional check can use fewer target values and runs, for example:

```bash
sudo env \
  TARGET_CONCURRENCY="0 16 32" \
  RUNS=1 \
  RESPONSE_DELAY_MS=3000 \
  HOLD_WINDOW_SEC=6 \
  bash testScripts/concurrency/pending_memory/run
```

Reduced runs validate the instrumentation and analysis pipeline but should not
be treated as reproducing the published measurements.

## Test Instrumentation

The pending-state experiment uses test-only instrumentation that is already
integrated into this paper branch and disabled by default.

Build OpenSSH with `KEM_TEST_INSTRUMENTATION` enabled before running this
experiment.

The instrumentation provides:

- KEMUAuth pending-state markers through
  `kem_test_inc_pending()` / `kem_test_dec_pending()`, producing
  `KEM_PENDING_INC` / `KEM_PENDING_DEC` events;
- client-side KEMUAuth response delay controlled by
  `KEMUAUTH_RESPONSE_DELAY_MS`;
- client-side ML-DSA-65 baseline pause controlled by
  `SIGAUTH_RESPONSE_DELAY_MS`, with `BASELINE_PAUSE_INC` /
  `BASELINE_PAUSE_DEC` markers.

These additions are guarded by:

```c
#ifdef KEM_TEST_INSTRUMENTATION
...
#endif
```

and therefore do not affect the normal build.

No additional source patch is required.

## Memory Measurement

The complete experiment-specific `sshd` process tree is placed in cgroup v2.

During the hold phase, the runner samples `memory.current` periodically and also
checks `memory.peak`. The larger observed value is used as the run's peak-memory
measurement.

The runner also records `pids.current` as an auxiliary indicator of the active
server-process count.

For KEMUAuth, the pending count is reconstructed from
`KEM_PENDING_INC` / `KEM_PENDING_DEC` events. After the server log has been
fully flushed, the complete log is scanned again to obtain the final observed
peak.

For the ML-DSA-65 baseline, the actual paused-connection count is reconstructed
from `BASELINE_PAUSE_INC` events in the client logs.

## Cleanup Validation

For KEMUAuth runs, the runner records the final pending count before server
shutdown and checks whether the pending state returns to zero after the
authentication attempts complete or terminate.

The runner also contains dedicated cleanup checks covering abnormal connection
termination paths.

## Output

Runtime results are written under:

```text
testScripts/concurrency/pending_memory/results/
```

The principal files are:

| File | Content |
|:---|:---|
| `summary.csv` | Per-run target count, observed pending count, peak memory, residual memory, final pending count, and cleanup status |
| `metadata.txt` | Environment and experiment parameters |
| `report.md` | Report generated by `analyze.py` |

The analyzer uses each run's `pending_estimate` as the independent variable and
fits KEMUAuth and ML-DSA-65 separately.

It then evaluates both fitted models at common normalized pending counts.

## Explicit KEMUAuth Challenge State

The paper-aligned implementation accounting uses:

```text
2384 bytes per pending KEMUAuth challenge
```

This is the explicitly retained KEMUAuth-specific challenge context, not the
total memory consumed by an SSH connection.

For normalized pending count `P`:

```text
M_explicit(P) = 2384 * P / 2^20 MiB
```

For example:

```text
M_explicit(172) ≈ 0.391 MiB
```

The much larger fitted per-connection memory slope is dominated by ordinary
OpenSSH process, socket, transport, and other per-connection state and must not
be interpreted as KEMUAuth challenge-state memory.

## Runtime Workspace

Temporary experiment state is stored under:

```text
testScripts/.work-pending-memory/
```

Runtime workspaces are excluded from Git.

## Requirements

The experiment requires:

- Linux with cgroup v2;
- root privileges for cgroup management;
- a KEMUAuth-enabled OpenSSH build compiled with
  `KEM_TEST_INSTRUMENTATION`;
- `mlkem768x25519-sha256` transport KEX support;
- ML-KEM-768 KEMUAuth support;
- ML-DSA-65 public-key authentication support;
- Python 3 for result analysis.
