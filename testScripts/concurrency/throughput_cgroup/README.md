# Concurrent Server Throughput and Resource Evaluation

This experiment evaluates KEMUAuth and ML-DSA-65 under concurrent SSH
connection load. It corresponds to the concurrent-server evaluation reported
in the extended version of the KEMUAuth paper.

The transport key exchange is fixed to `mlkem768x25519-sha256`, and the server
host-key algorithm is fixed to `ssh-mldsa-65`. The experiments run over
loopback without emulated RTT or packet loss.

The complete `sshd` process tree is pinned to two dedicated CPU cores and
placed in a cgroup v2, while client workers use a disjoint CPU set. Each worker
repeatedly establishes a fresh SSH connection, completes authentication,
executes `true`, and closes the connection.

## Published Configuration

The published experiment uses:

- Concurrency levels: `1 8 16 32 64`
- Independent runs per configuration: `5`
- Warm-up duration: `5` seconds
- Measurement duration: `30` seconds
- Cooldown duration: `10` seconds
- Transport KEX: `mlkem768x25519-sha256`
- Server host key: `ssh-mldsa-65`
- Compared client-authentication methods:
  - KEMUAuth with ML-KEM-768
  - `publickey` with ML-DSA-65
- Network: loopback, without artificial RTT or packet loss
- Server CPU allocation: two dedicated cores
- Client CPU allocation: disjoint from the server CPU set

The reported values are medians over the five independent runs.

## Running the Experiment

To reproduce the published configuration:

```bash
sudo bash testScripts/concurrency/throughput_cgroup/run
```

The default parameters of the script match the published experiment.

For a shorter functional check, the parameters may be overridden explicitly.
For example:

```bash
sudo env CONCURRENCY_LIST="1 16 64" RUNS=1 \
  WARMUP_SECONDS=2 MEASURE_SECONDS=5 COOLDOWN_SECONDS=1 \
  bash testScripts/concurrency/throughput_cgroup/run
```

Such reduced runs are intended only to validate the experimental pipeline and
do not reproduce the statistical scale of the published experiment.

## Environment Variables

| Variable | Default | Description |
|:---|:---|:---|
| `CONCURRENCY_LIST` | `1 8 16 32 64` | Concurrent client-worker counts |
| `RUNS` | `5` | Independent runs per method and concurrency level |
| `WARMUP_SECONDS` | `5` | Warm-up duration before measurement |
| `MEASURE_SECONDS` | `30` | Measurement duration |
| `COOLDOWN_SECONDS` | `10` | Cooldown duration after each run |
| `SERVER_CPUSET` | auto | Dedicated server CPU set |
| `CLIENT_CPUSET` | auto | Client CPU set disjoint from the server set |
| `MAX_STARTUPS` | `1024` | `sshd` `MaxStartups` setting |

## Output

Runtime output is written under:

```text
testScripts/concurrency/throughput_cgroup/results/
```

The principal files are:

| File | Content |
|:---|:---|
| `raw_runs.csv` | Per-connection latency and outcome records |
| `summary.csv` | Per-run throughput, CPU, memory, and p95 latency |
| `metadata.txt` | Environment and experiment configuration |
| `report.md` | Generated aggregate report |

Published numerical results are preserved separately in:

```text
testScripts/concurrency/throughput_cgroup/published_results.md
```

Runtime experiments do not overwrite `published_results.md`.

## Measurement Method

For each concurrency level, the experiment alternates between KEMUAuth and
ML-DSA-65 authentication runs.

For each run:

1. A dedicated `sshd` instance is started inside a cgroup v2.
2. The complete server process tree is restricted to the configured server CPU
   set.
3. Client workers are restricted to a disjoint CPU set.
4. A warm-up phase is executed before measurement.
5. During the measurement window, workers repeatedly establish fresh SSH
   connections, authenticate, execute `true`, and disconnect.
6. Server CPU consumption and aggregate memory are measured through cgroup v2.
7. Per-connection completion time and outcome are recorded.
8. The experiment waits for the configured cooldown period before the next run.

The aggregate report uses the median across independent runs for each
authentication method and concurrency level.

## Reported Metrics

The experiment records:

- successful connection throughput in connections per second;
- server CPU utilization;
- server CPU time per successfully completed connection;
- 95th-percentile end-to-end connection latency;
- aggregate peak server memory;
- attempted, successful, and failed connection counts.

Throughput is computed from successfully completed SSH connections.

The published experiment shows that KEMUAuth has a modest throughput and
per-connection CPU advantage when spare server capacity is available. As the
two-core server approaches saturation, both authentication methods converge to
similar throughput because total SSH connection processing becomes dominated
by shared transport, server-authentication, process-management, packet-processing,
and scheduling costs.

## Runtime Workspace

Temporary keys, SSH configuration files, worker data, and intermediate
measurement files are stored under the experiment runtime workspace:

```text
testScripts/.work-concurrency-throughput/
```

Runtime workspaces are excluded from Git and are not part of the published
artifact.

## Requirements

The experiment requires:

- Linux with cgroup v2;
- root privileges for cgroup and CPU-affinity configuration;
- KEMUAuth-enabled OpenSSH;
- `mlkem768x25519-sha256` transport key exchange support;
- ML-KEM-768 KEMUAuth support;
- ML-DSA-65 signature authentication support.
