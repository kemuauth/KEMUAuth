# Concurrent Server Evaluation — Published Results

This file preserves the numerical results reported in the extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

The experiment compares KEMUAuth with ML-DSA-65 client authentication under
controlled concurrent SSH connection load.

## Published Configuration

- Transport KEX: `mlkem768x25519-sha256`
- Server host-key algorithm: `ssh-mldsa-65`
- Compared client-authentication methods:
  - KEMUAuth with ML-KEM-768
  - ML-DSA-65
- Network: loopback
- Artificial RTT: none
- Artificial packet loss: none
- Server CPU allocation: two dedicated CPU cores
- Client CPU allocation: disjoint from the server CPU set
- Concurrency levels: `1 8 16 32 64`
- Independent runs per configuration: `5`
- Warm-up duration: `5` seconds
- Measurement duration: `30` seconds
- Cooldown duration: `10` seconds

Each client worker repeatedly establishes a fresh SSH connection, completes
authentication, executes `true`, and closes the connection.

The values below are the medians across the five independent runs for each
authentication method and concurrency level.

## Concurrent SSH Throughput and Server CPU Cost

| N | Authentication Method | Successful Throughput (conn/s) | Server CPU Utilization (%) | CPU per Connection (ms) |
|---:|:---|---:|---:|---:|
| 1  | KEMUAuth  | 11.36  | 11.2 | 19.67 |
| 1  | ML-DSA-65 | 10.87  | 10.7 | 19.70 |
| 8  | KEMUAuth  | 84.48  | 74.4 | 17.57 |
| 8  | ML-DSA-65 | 81.75  | 72.5 | 17.72 |
| 16 | KEMUAuth  | 107.99 | 97.6 | 18.06 |
| 16 | ML-DSA-65 | 106.46 | 97.0 | 18.22 |
| 32 | KEMUAuth  | 107.65 | 99.5 | 18.49 |
| 32 | ML-DSA-65 | 106.48 | 99.5 | 18.69 |
| 64 | KEMUAuth  | 106.27 | 99.7 | 18.97 |
| 64 | ML-DSA-65 | 105.90 | 99.8 | 19.06 |

## Tail Latency and Aggregate Memory

| N | Authentication Method | 95th-Percentile Latency (ms) | Peak Memory (MB) |
|---:|:---|---:|---:|
| 1  | KEMUAuth  | 79  | 9.3 |
| 1  | ML-DSA-65 | 83  | 9.3 |
| 8  | KEMUAuth  | 94  | 39.6 |
| 8  | ML-DSA-65 | 97  | 40.1 |
| 16 | KEMUAuth  | 158 | 74.4 |
| 16 | ML-DSA-65 | 161 | 74.6 |
| 32 | KEMUAuth  | 317 | 133.3 |
| 32 | ML-DSA-65 | 321 | 133.5 |
| 64 | KEMUAuth  | 665 | 242.9 |
| 64 | ML-DSA-65 | 680 | 244.4 |

## Throughput Difference

The successful-throughput improvements of KEMUAuth relative to ML-DSA-65 are:

| N | KEMUAuth Throughput Gain |
|---:|---:|
| 1  | 4.5% |
| 8  | 3.3% |
| 16 | 1.4% |
| 32 | 1.1% |
| 64 | 0.35% |

The difference narrows as the two-core server approaches CPU saturation.
At higher concurrency, common SSH costs such as transport key exchange,
server authentication, process management, packet processing, and scheduling
increasingly dominate the per-authentication primitive difference.

Aggregate peak memory remains closely matched between the two authentication
methods. The protocol-specific memory associated with pending KEMUAuth
challenges is evaluated separately in the pending-state experiment.

## Reproduction Note

These are the numerical values reported in the extended paper.

Files generated under:

```text
testScripts/concurrency/throughput_cgroup/results/
```

represent a new local reproduction run and may vary with hardware, operating
system state, CPU topology, scheduling, and software versions.

Runtime experiments do not overwrite this file.
