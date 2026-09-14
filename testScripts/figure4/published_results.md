# Figure 4 / Table IX — Published Results

This file records the numerical client-observed end-to-end SSH latency results
published for **Figure 4** of the ICNP 2026 paper and **Table IX** of the
extended arXiv version.

These values are the canonical published results and are provided for
comparison with independently reproduced runs.

## Experimental Configuration

- Transport key exchange: `mlkem768x25519-sha256`
- TCP MSS: 1460 bytes
- TCP initial congestion window: 10 MSS
- Close RTT: approximately 37 ms
- Intermediate RTT: approximately 67 ms
- Long RTT: approximately 163 ms
- Measurement: client-observed wall-clock latency of a fresh SSH invocation
- Published measurement count: 5,000 handshakes per configuration

## Published Latency Results

| Client Authentication | Server Authentication | Notation | 37 ms Mean | 37 ms P50 | 37 ms P95 | 67 ms Mean | 67 ms P50 | 67 ms P95 | 163 ms Mean | 163 ms P50 | 163 ms P95 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Ed25519 | Ed25519 | `ed25519` | 522.01 | 522.04 | 525.07 | 853.14 | 852.54 | 858.96 | 1911.21 | 1912.88 | 1918.35 |
| ML-DSA-65 + Ed25519 | ML-DSA-65 + Ed25519 | `h-md65` | 524.53 | 524.67 | 527.08 | 855.31 | 854.60 | 861.19 | 1913.69 | 1915.50 | 1920.41 |
| SLH-DSA-SHA2-192f + Ed25519 | SLH-DSA-SHA2-192f + Ed25519 | `h-sd192f` | 644.52 | 645.29 | 649.93 | 1033.83 | 1033.59 | 1042.34 | 2283.98 | 2285.79 | 2292.09 |
| ML-KEM-768 + Ed25519 | ML-DSA-65 + Ed25519 | `h-mk768-md65` | 523.49 | 523.68 | 526.06 | 852.82 | 852.37 | 858.57 | 1913.37 | 1915.46 | 1920.11 |
| ML-KEM-768 + Ed25519 | SLH-DSA-SHA2-192f + Ed25519 | `h-mk768-sd192f` | 581.58 | 582.00 | 585.53 | 946.05 | 944.51 | 953.30 | 2096.68 | 2098.43 | 2103.70 |
| Ed25519 → ML-DSA-65 | ML-DSA-65 + Ed25519 | `ms-md65` | 603.55 | 603.85 | 606.64 | 997.94 | 992.99 | 1000.43 | 2247.47 | 2249.28 | 2254.37 |
| Ed25519 → ML-KEM-768 | ML-DSA-65 + Ed25519 | `ms-mk768` | 600.16 | 600.32 | 603.14 | 990.03 | 988.66 | 996.58 | 2244.87 | 2246.80 | 2251.31 |
| ML-KEM-768 | ML-DSA-65 | `mk768-md65` | 518.80 | 518.84 | 521.24 | 849.51 | 848.75 | 854.14 | 1910.46 | 1911.72 | 1916.49 |

All latency values are in milliseconds.

## Reproduction Note

A local execution of:

```bash
bash testScripts/figure4/run
```

writes independently reproduced measurements under:

```text
testScripts/figure4/results/
```

The internal directories `test2-C`, `test2-I`, and `test2-L` correspond to the
close, intermediate, and long RTT profiles, respectively.

Locally reproduced values may differ from the published measurements because
of hardware, operating-system state, CPU behavior, scheduling, and background
load.

The values in this file should therefore be treated as the reference values
reported in the published paper, while files under `results/` should be treated
as outputs of a particular reproduction run.
