# Figure 3 / Table VIII — Published Results

This file records the numerical results published for the client-authentication
comparison in **Figure 3** of the ICNP 2026 paper and **Table VIII** of the
extended arXiv version.

These values are the canonical published results for this experiment. They are
provided for comparison with independently reproduced runs and are not generated
from the reduced default sample count used by `testScripts/figure3/run`.

## Experimental Configuration

The published Figure 3 evaluation uses:

- Transport key exchange: `mlkem768x25519-sha256`
- Server authentication: Ed25519
- RTT: approximately 67 ms
- TCP MSS: 1460 bytes
- TCP initial congestion window: 10 MSS
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Published measurement count: 5,000 handshakes per configuration

## Published Latency Results

| Client Algorithm | Notation | NIST PQ Category | Mean (ms) | P50 (ms) | P95 (ms) |
| --- | --- | --- | ---: | ---: | ---: |
| Ed25519 | `ed25519` | Classical only | 842.042 | 841.962 | 845.765 |
| ML-DSA-44 | `md44` | Level 2 | 841.720 | 841.622 | 844.368 |
| ML-DSA-65 | `md65` | Level 3 | 841.792 | 841.692 | 845.367 |
| ML-DSA-87 | `md87` | Level 5 | 841.912 | 841.791 | 845.699 |
| Falcon-512 | `falcon512` | Level 1 | 841.746 | 841.656 | 845.233 |
| Falcon-1024 | `falcon1024` | Level 5 | 841.940 | 841.850 | 846.634 |
| SLH-DSA-SHA2-128f | `sd128f` | Level 1 | 920.703 | 920.556 | 928.641 |
| SLH-DSA-SHA2-192f | `sd192f` | Level 3 | 929.522 | 929.319 | 934.724 |
| SLH-DSA-SHA2-256f | `sd256f` | Level 5 | 1018.098 | 1017.955 | 1025.191 |
| ML-KEM-512 | `mk512` | Level 1 | 840.767 | 840.666 | 843.290 |
| ML-KEM-768 | `mk768` | Level 3 | 840.779 | 840.681 | 843.480 |
| ML-KEM-1024 | `mk1024` | Level 5 | 840.805 | 840.694 | 843.578 |
| Password (yescrypt) | `password` | — | 785.648 | 785.446 | 790.494 |

Figure 3 visualizes the mean, median, and P95 values above. Table VIII of the
extended arXiv version provides the corresponding numerical results.

## Reproduction Note

A new local execution of `testScripts/figure3/run` writes independently
reproduced measurements under:

`testScripts/figure3/results/`

Those locally generated files represent a new experiment run and may differ
slightly from the published values because of hardware, operating-system state,
CPU behavior, and background load.

The values in this file should therefore be treated as the reference values
reported in the published paper, while files under `results/` should be treated
as outputs of a particular reproduction run.
