# Ciphertext Robustness — Artifact Results

This file preserves the malformed-ciphertext and local decapsulation timing
checks associated with the KEMUAuth ICNP 2026 artifact.

These checks are implementation-level sanity tests. They are not part of the
main performance evaluation and should not be interpreted as a constant-time
proof, a comprehensive side-channel analysis, or a complete implementation
security assessment.

## Historical ICNP Artifact Results

The original ICNP artifact tested eight server-supplied ciphertext classes at
the protocol level:

- valid;
- one-bit mutation;
- multi-bit mutation;
- random ciphertext;
- all-zero ciphertext;
- all-`ff` ciphertext;
- truncated ciphertext;
- extended ciphertext.

Each class was tested 50 times.

### Protocol-Level Observable Behavior

| Ciphertext Class | Tests | Client Returns KEM Response? | Authentication Result | p50 Challenge-to-Response (ms) | p95 Challenge-to-Response (ms) | Crashes or Errors |
|:---|---:|:---:|:---|---:|---:|---:|
| Valid | 50 | YES | 50 success | 5.1 | 5.2 | 0 |
| One-bit flip | 50 | YES | 50 authentication failures | 5.1 | 5.2 | 0 |
| Multi-bit flip | 50 | YES | 50 authentication failures | 5.1 | 5.2 | 0 |
| Random | 50 | YES | 50 authentication failures | 5.1 | 5.3 | 0 |
| All-zero | 50 | YES | 50 authentication failures | 5.1 | 5.2 | 0 |
| All-`ff` | 50 | YES | 50 authentication failures | 5.1 | 5.3 | 0 |
| Truncated | 50 | YES | 50 authentication failures | 5.1 | 5.4 | 0 |
| Extended | 50 | YES | 50 authentication failures | 5.1 | 5.2 | 0 |

The historical artifact therefore observed successful authentication only for
the valid ciphertext. All mutated ciphertext classes resulted in
authentication failure, and no server crashes were observed.

### Historical Local ML-KEM-768 Decapsulation Timing

The artifact also included a local ML-KEM-768 decapsulation timing sanity
check with 500 measurements per ciphertext class.

| Ciphertext Class | Samples | Median (ns) | 5th–95th Percentile (ns) | Median Difference |
|:---|---:|---:|:---|---:|
| Valid | 500 | 8697 | 8551–9789 | — |
| One-bit flip | 500 | 8660 | 8552–9770 | -0.43% |
| Multi-bit flip | 500 | 8690 | 8550–9603 | -0.08% |
| Random | 500 | 8670 | 8554–9970 | -0.31% |
| All-zero | 500 | 8676 | 8551–9765 | -0.24% |
| All-`ff` | 500 | 8668 | 8556–9904 | -0.33% |

The measured distributions showed no coarse timing separation among these
ciphertext classes in the evaluated environment.

Absolute timings are platform-dependent. These measurements should therefore
be interpreted only as a coarse timing sanity check.

## Current Hardened Paper Branch

During preparation of the long-term project repository, the original
malformed-ciphertext test path was audited.

Two implementation issues were corrected in the paper-aligned branch.

First, the KEMUAuth client now verifies that the received ciphertext length
matches the ciphertext length required by the negotiated KEM before invoking
decapsulation:

```text
received ciphertext
        |
        v
ciphertext length == expected KEM ciphertext length?
        |
        +-- no  -> reject before decapsulation
        |
        +-- yes -> perform KEM decapsulation
```

Second, the test-only server mutation instrumentation was rewritten so that
extended ciphertexts are constructed in a correctly sized temporary buffer.
The mutation hook no longer changes a ciphertext length without allocating the
corresponding storage.

These changes do not alter the valid KEMUAuth protocol flow.

The original implementation corresponding to the ICNP artifact remains
preserved by the repository tag:

```text
icnp-2026-original-artifact
```

## Hardened Protocol Behavior

A functional smoke test of the hardened implementation used three trials per
ciphertext class.

| Ciphertext Class | Trials | KEM Responses | Result | Server Crashes |
|:---|---:|---:|:---|---:|
| Valid | 3 | 3/3 | 3 authentication successes | 0 |
| One-bit flip | 3 | 3/3 | 3 authentication rejections | 0 |
| Multi-bit flip | 3 | 3/3 | 3 authentication rejections | 0 |
| Random | 3 | 3/3 | 3 authentication rejections | 0 |
| All-zero | 3 | 3/3 | 3 authentication rejections | 0 |
| All-`ff` | 3 | 3/3 | 3 authentication rejections | 0 |
| Truncated | 3 | 0/3 | 3 rejected before response | 0 |
| Extended | 3 | 0/3 | 3 rejected before response | 0 |

The hardened implementation therefore distinguishes two malformed-input cases.

For same-length malformed ciphertexts:

```text
malformed ciphertext
        |
        v
valid KEM ciphertext length
        |
        v
ML-KEM decapsulation
        |
        v
KEM response
        |
        v
server response verification fails
        |
        v
authentication rejected
```

For wrong-length ciphertexts:

```text
truncated / extended ciphertext
        |
        v
ciphertext-length validation fails
        |
        v
reject before KEM decapsulation
        |
        v
no KEM response
```

The changed behavior for truncated and extended ciphertexts is intentional
post-artifact hardening. It should not be confused with the behavior of the
historical ICNP artifact preserved above.

## Current Local Timing Check

The current runner builds the microbenchmark against a real liboqs
implementation. It does not silently fall back to a dummy computation when
liboqs is unavailable.

A local run uses:

```text
ML-KEM-768
100 warm-up iterations
500 measured decapsulations per ciphertext class
```

and compares:

```text
valid
onebit
multibit
random
allzero
allff
```

The generated timing measurements are stored under the runtime `results/`
directory and are intentionally not treated as fixed published values because
absolute microbenchmark timings depend strongly on the execution environment.

## Reproduction

Run the complete check with:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode all
```

Run only the protocol-level malformed-ciphertext check with:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode protocol
```

Run only the local ML-KEM-768 timing check with:

```bash
bash testScripts/implementation_checks/ciphertext_robustness/run \
  --mode local
```

Runtime measurements are written beneath:

```text
testScripts/implementation_checks/ciphertext_robustness/results/
```

The runtime results do not overwrite this file.

## Assurance Boundary

These checks provide evidence that:

- valid ciphertexts follow the expected authentication path;
- same-length malformed ciphertexts do not authenticate;
- wrong-length ciphertexts are rejected before decapsulation in the hardened
  implementation;
- the tested malformed inputs do not crash the server;
- the evaluated same-length ciphertext classes show no obvious coarse
  decapsulation-timing separation.

They do **not** establish:

- formally verified implementation security;
- constant-time execution;
- absence of microarchitectural leakage;
- resistance to all malformed-input strategies;
- comprehensive side-channel resistance.

The checks should therefore be interpreted as targeted implementation
robustness and timing sanity tests.
