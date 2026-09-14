# Network-Sensitivity Evaluation

This directory contains the network-sensitivity experiments reported in the
extended version of:

> **A Drop-in KEM Replacement for Client Signatures in Post-Quantum SSH**
> IEEE ICNP 2026.

The experiments extend the representative-RTT evaluation by studying:

1. end-to-end SSH handshake latency across a dense RTT sweep; and
2. latency and TCP retransmission behavior under random packet loss.

Both experiments compare KEMUAuth with ML-KEM-768 against ML-DSA-65 client
authentication while keeping the SSH transport and server authentication fixed.

## Directory Structure

| Directory | Experiment | Published Results |
|:---|:---|:---|
| `rtt_scan/` | RTT sensitivity from 0 to 200 ms | [`published_results.md`](rtt_scan/published_results.md) |
| `loss/` | Random packet-loss sensitivity at approximately 67 ms RTT | [`published_results.md`](loss/published_results.md) |

The top-level entry point is:

```bash
sudo bash testScripts/network_sensitivity/run
```

It runs both experiments by default.

Individual experiments can also be selected with:

```bash
sudo bash testScripts/network_sensitivity/run --mode rtt
sudo bash testScripts/network_sensitivity/run --mode loss
sudo bash testScripts/network_sensitivity/run --mode all
```

## Common Experimental Conditions

Unless overridden explicitly, both experiments use:

| Parameter | Value |
|:---|:---|
| Transport KEX | `mlkem768x25519-sha256` |
| Server host-key authentication | Ed25519 |
| KEMUAuth algorithm | ML-KEM-768 |
| Signature baseline | ML-DSA-65 |
| TCP initial congestion window | 10 MSS |

The measured value is the client-observed end-to-end wall-clock latency of a
fresh SSH invocation, including connection establishment, key exchange, user
authentication, and completion of the trivial remote command (`true`).

## RTT Sensitivity

Runner:

```bash
sudo bash testScripts/network_sensitivity/rtt_scan/run
```

The default RTT sweep is:

```text
0 20 40 60 80 100 120 160 200 ms
```

The repository runner uses the following practical default:

```text
500 measured connections per RTT point per authentication method
```

A shorter functional check can be run with, for example:

```bash
sudo env \
  ITERATIONS=50 \
  RTT_LIST="0 40 80 120" \
  bash testScripts/network_sensitivity/rtt_scan/run
```

To use the measurement scale stated for the published end-to-end evaluation:

```bash
sudo env \
  ITERATIONS=5000 \
  bash testScripts/network_sensitivity/rtt_scan/run
```

Generated files are written under:

```text
testScripts/network_sensitivity/rtt_scan/results/
```

and include:

```text
rtt_raw.csv
rtt_summary.csv
rtt_report.md
```

The numerical values reported in the extended paper are preserved separately in:

```text
testScripts/network_sensitivity/rtt_scan/published_results.md
```

## Packet-Loss Sensitivity

Runner:

```bash
sudo bash testScripts/network_sensitivity/loss/run
```

The default loss-rate sweep is:

```text
0 0.1 0.5 1.0 2.0 %
```

with an RTT of approximately:

```text
67 ms
```

The repository runner uses repeated measurement batches. Its practical default is:

```text
5 repetitions
200 measured connections per repetition and authentication method
```

Thus, the default local run collects:

```text
1000 measured connections per loss rate and authentication method
```

The repetitions are independent repeated batches. They are not explicitly
seeded `tc/netem` random-number streams.

A shorter functional check can be run with:

```bash
sudo env \
  REPETITIONS=2 \
  ITERATIONS_PER_REPETITION=50 \
  bash testScripts/network_sensitivity/loss/run
```

To collect 5,000 handshakes per loss-rate configuration while retaining five
repetitions:

```bash
sudo env \
  REPETITIONS=5 \
  ITERATIONS_PER_REPETITION=1000 \
  bash testScripts/network_sensitivity/loss/run
```

Generated files are written under:

```text
testScripts/network_sensitivity/loss/results/
```

and include:

```text
loss_raw.csv
loss_summary.csv
loss_retrans.csv
loss_report.md
```

The numerical values reported in the extended paper are preserved separately in:

```text
testScripts/network_sensitivity/loss/published_results.md
```

## Published Results vs. Local Reproduction

The `published_results.md` files contain the numerical values reported in the
extended paper.

The default runner settings are intentionally smaller than the published
measurement scale so that users can validate the build, authentication setup,
network emulation, and result-processing pipeline without immediately running
the full experiment.

Results produced by a new local run may differ from the published values because
of hardware, operating-system scheduling, software versions, and network-stack
behavior.

For paper-scale reproduction, explicitly select the larger measurement counts
shown above.

## Requirements

The experiments require:

- a Linux environment with `tc/netem` and `ip route`;
- root privileges for network-emulation and TCP-route configuration;
- a KEMUAuth-enabled OpenSSH build;
- `mlkem768x25519-sha256` transport KEX support;
- ML-KEM-768 KEMUAuth support;
- ML-DSA-65 public-key authentication support.

The scripts use loopback network emulation and restore their experiment-specific
state when execution completes normally.
