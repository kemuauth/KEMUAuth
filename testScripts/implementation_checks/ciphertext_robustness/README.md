# Ciphertext Robustness and Decapsulation Timing Checks

This directory contains targeted implementation checks for KEMUAuth handling of
server-supplied KEM ciphertexts.

The checks were motivated by the fact that, during KEMUAuth client
authentication, the SSH server supplies a ciphertext that is decapsulated
under the client's long-term KEM secret key.

The evaluation contains two complementary components:

1. a protocol-level malformed-ciphertext robustness check;
2. a local ML-KEM-768 decapsulation timing sanity check.

These checks are intentionally narrower than the main KEMUAuth performance
evaluation. They should not be interpreted as a proof of constant-time
execution or as a comprehensive side-channel assessment.

Historical ICNP artifact results and the behavior of the current hardened
paper branch are documented in:

```text
testScripts/implementation_checks/ciphertext_robustness/artifact_results.md
```

## Protocol-Level Robustness Check

The protocol-level check runs a mutation-enabled KEMUAuth server and sends
different ciphertext classes to the client.

The tested classes are:

```text
valid
onebit
multibit
random
allzero
allff
truncated
extended
```

The first six classes preserve the expected ML-KEM-768 ciphertext length.

The last two deliberately change the ciphertext length:

```text
truncated = expected length - 1 byte
extended  = expected length + 1 byte
```

### Same-Length Malformed Ciphertexts

For:

```text
onebit
multibit
random
allzero
allff
```

the ciphertext length remains valid.

The expected behavior is:

```text
server sends malformed ciphertext
        |
        v
client accepts the encoded ciphertext length
        |
        v
ML-KEM-768 decapsulation
        |
        v
client derives and sends KEM_RESPONSE
        |
        v
server compares against its expected response
        |
        v
authentication is rejected
```

This exercises the ML-KEM decapsulation path with attacker-controlled
same-length ciphertexts.

### Wrong-Length Ciphertexts

The current paper branch performs an explicit ciphertext-length check before
calling the KEM decapsulation routine.

For:

```text
truncated
extended
```

the expected behavior is therefore:

```text
server sends wrong-length ciphertext
        |
        v
client validates ciphertext length
        |
        v
length mismatch
        |
        v
reject before ML-KEM decapsulation
        |
        v
no KEM_RESPONSE
```

This behavior is a post-artifact robustness hardening change.

The original ICNP artifact behavior is preserved separately in
`artifact_results.md` and by the repository tag:

```text
icnp-2026-original-artifact
```

## Test-Only Mutation Instrumentation

The server-side mutation mechanism is integrated directly into the paper branch
and is disabled in normal builds.

The instrumentation is guarded by:

```c
#ifdef KEM_TEST_MUTATION
...
#endif
```

The mutation-enabled build is used only for the protocol-level robustness
check.

The mutation hook constructs temporary wire ciphertexts and does not modify the
server's retained original ciphertext.

In particular, the `extended` case allocates a correctly sized temporary
buffer before appending the additional byte. This avoids the out-of-bounds read
that could result from increasing a ciphertext length without increasing its
storage.

The runner automatically builds the mutation-enabled server before the
protocol check and restores the normal server binaries afterward.

## Local ML-KEM-768 Decapsulation Timing Check

The local microbenchmark directly invokes ML-KEM-768 decapsulation through
liboqs.

It compares six equal-length ciphertext classes:

```text
valid
onebit
multibit
random
allzero
allff
```

The default configuration uses:

```text
Warm-up iterations:       100
Measurements per class:   500
CPU core:                  0
```

The benchmark reports:

- mean decapsulation time;
- median decapsulation time;
- 5th percentile;
- 95th percentile;
- relative median difference from the valid-ciphertext class.

The benchmark must use a real liboqs implementation.

The runner checks, in order:

1. the repository-local liboqs build;
2. a system liboqs available through `pkg-config`;
3. a liboqs installation under `/usr/local`.

If no real liboqs implementation is available, the benchmark fails instead of
falling back to a dummy computation.

For the repository-local build used by this project, the runner uses:

```text
headers: oqs/include/
library: oqs-test/tmp/lib/
```

## Running the Checks

Run both checks:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode all
```

Run only the protocol-level malformed-ciphertext check:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode protocol
```

Run only the local decapsulation timing check:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode local
```

The default protocol-level configuration uses:

```text
50 trials per same-length ciphertext class
50 trials per wrong-length ciphertext class
```

For a short functional check, the counts can be reduced explicitly:

```bash
env \
  SAME_LEN_TESTS=3 \
  DIFF_LEN_TESTS=3 \
  bash testScripts/implementation_checks/ciphertext_robustness/run \
    --mode protocol
```

Such reduced runs validate the implementation and analysis pipeline but are not
intended to reproduce the statistical scale of the historical artifact check.

The local benchmark parameters can also be overridden:

```bash
env \
  DECAPS_WARMUP=50 \
  DECAPS_ITERATIONS=200 \
  DECAPS_CORE=0 \
  bash testScripts/implementation_checks/ciphertext_robustness/run \
    --mode local
```

## Output Files

Runtime results are written under:

```text
testScripts/implementation_checks/ciphertext_robustness/results/
```

The principal files are:

| File | Description |
|:---|:---|
| `protocol_raw.csv` | Per-trial protocol-level observations |
| `protocol_summary.csv` | Aggregated results by ciphertext class |
| `protocol_report.md` | Human-readable protocol-level report |
| `local_decaps_report.md` | Local ML-KEM-768 decapsulation timing report |

Runtime results are local measurements and are not tracked as canonical
published values.

Historical artifact results are preserved separately in:

```text
artifact_results.md
```

## Protocol Analysis

The protocol analyzer classifies a client response only when the recorded
response type is:

```text
KEM_RESPONSE
```

This distinction matters for the hardened implementation.

For example:

```text
same-length malformed ciphertext
    -> KEM_RESPONSE
    -> authentication rejected

wrong-length ciphertext
    -> no KEM_RESPONSE
    -> rejected before decapsulation
```

The analyzer therefore does not infer that a response occurred merely because a
connection terminated without a timeout or transport error.

## Build and Restore Behavior

For `--mode protocol`, the top-level runner performs:

```text
build mutation-enabled server
        |
        v
run protocol-level checks
        |
        v
restore normal server binaries
```

For `--mode all`, it performs:

```text
build mutation-enabled server
        |
        v
run protocol-level checks
        |
        v
run local decapsulation benchmark
        |
        v
restore normal server binaries
```

A cleanup trap also attempts to restore the normal server build if the
protocol-level experiment terminates early.

Changing compiler flags alone does not necessarily invalidate existing object
files, so the backend explicitly removes the affected server objects and
binaries before rebuilding.

## Runtime Workspace

Temporary experiment files and the compiled local microbenchmark are stored
under the runtime workspace rather than in the source directory.

The default workspace is beneath:

```text
testScripts/.work-*
```

These runtime workspaces are ignored by Git.

The source directory therefore contains only the persistent experiment files:

```text
README.md
analyze.py
artifact_results.md
microbench_decaps.c
run
```

## Reproducibility Notes

The protocol-level check starts a fresh `sshd` instance for each trial. This is
intentional and keeps the mutation state isolated between connections.

Absolute timing values depend on:

- processor model and frequency;
- CPU scheduling;
- operating-system activity;
- compiler options;
- liboqs version and build configuration;
- virtualization and power-management behavior.

Timing results should therefore be compared primarily within the same
experimental environment.

The absence of a coarse timing separation in this microbenchmark does not
establish constant-time execution.

## Assurance Boundary

These checks provide targeted evidence that:

- valid ciphertexts follow the expected KEMUAuth path;
- same-length malformed ciphertexts do not authenticate;
- wrong-length ciphertexts are rejected before decapsulation in the current
  hardened implementation;
- the tested malformed inputs do not crash the server;
- the tested equal-length ciphertext classes do not exhibit an obvious coarse
  decapsulation-timing separation in the evaluated environment.

They do not establish:

- formally verified implementation security;
- constant-time behavior;
- absence of cache or other microarchitectural leakage;
- resistance to fault injection;
- resistance to every malformed-input strategy;
- comprehensive side-channel security.

These experiments should therefore be treated as implementation robustness and
timing sanity checks rather than as a complete implementation-security
evaluation.
