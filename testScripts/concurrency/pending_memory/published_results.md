# Pending Authentication State Memory — Published Results

This file preserves the numerical results reported in the extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

The experiment estimates server-memory scaling as the number of simultaneously
pending authentication attempts increases.

KEMUAuth and ML-DSA-65 are fitted independently using the actually observed
pending or paused connection counts from repeated runs. The fitted models are
then evaluated at the same normalized pending count `P`.

## Published Experiment Metadata

- Transport KEX: `mlkem768x25519-sha256`
- Server host-key algorithm: `ssh-mldsa-65`
- Memory accounting: cgroup v2
- Independent runs per target configuration: 5
- KEMUAuth response delay: 20000 ms
- Hold window: 35 s

Because individual runs may reach slightly different maximum pending counts,
the published table is based on independent linear fits rather than direct
comparison of unmatched raw memory peaks.

## Fitted Memory Models

The fitted models used for the published results are:

```text
M_KEMUAuth(P) ≈ 24.5413 + 3.10889 * P   MiB
M_ML-DSA(P)   ≈ 20.2618 + 3.11238 * P   MiB
```

The two slopes are both approximately:

```text
3.11 MiB per pending connection
```

This growth is dominated by ordinary OpenSSH process, socket, transport, and
other per-connection state. It must not be interpreted as the memory cost of
the KEMUAuth challenge itself.

## Published Normalized Memory Comparison

| Normalized Pending Connections P | Estimated Peak Memory: KEMUAuth (MiB) | Estimated Peak Memory: ML-DSA-65 (MiB) | Memory Difference (MiB) | Explicit KEM State (MiB) |
|---:|---:|---:|---:|---:|
| 16  | 74.28  | 70.06  | 4.22 | 0.036 |
| 32  | 124.03 | 119.86 | 4.17 | 0.073 |
| 64  | 223.51 | 219.45 | 4.05 | 0.146 |
| 128 | 422.48 | 418.65 | 3.83 | 0.291 |
| 172 | 559.27 | 555.59 | 3.67 | 0.391 |

## Explicit KEMUAuth Challenge State

The implementation accounting used in the paper identifies:

```text
2384 bytes per pending KEMUAuth challenge
```

of explicitly retained KEMUAuth-specific challenge context.

Therefore:

```text
M_explicit(P) = 2384 * P / 2^20 MiB
```

and, at the largest normalized count reported in the paper:

```text
M_explicit(172)
    = 2384 * 172 / 2^20
    ≈ 0.391 MiB
```

The approximately 4 MiB fitted aggregate-memory offset must not be interpreted
as 4 MiB of challenge state per connection. It includes fixed implementation
differences, allocator behavior, page granularity, and other process-level
effects.

## Cleanup Observation

Pending KEMUAuth state returns to zero after authentication completion or
connection termination in the evaluated runs.

The result therefore supports the conclusion that the additional
protocol-specific KEMUAuth state is small and bounded and does not materially
change aggregate concurrent-memory scaling.

## Reproduction Note

These values are the published reference results.

A new run of:

```text
testScripts/concurrency/pending_memory/run
```

produces raw measurements in `results/`. The accompanying `analyze.py` fits
KEMUAuth and ML-DSA-65 independently from the newly observed pending counts and
may therefore produce different coefficients and normalized estimates on a
different machine.

Runtime experiments do not overwrite this file.
