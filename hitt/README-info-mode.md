# HITT Info Mode

**Info mode** (`-m info`) displays read-only summaries about a Helix environment. It is **under active development** — sub-commands and output may change between HITT builds.

```bash
bash hitt.sh -m "info cluster"
bash hitt.sh -m info
bash hitt.sh -m "info full"
bash hitt.sh -m "info help"
```

If you omit the sub-command (`bash hitt.sh -m info`), HITT defaults to **`full`**.

Built-in summary: `bash hitt.sh -m "info help"`

## Requirements

| Sub-command | Typical requirements |
|-------------|----------------------|
| `cluster` | Valid **kubeconfig** and **kubectl** access to list nodes and metrics (`kubectl top nodes` when the metrics server is available). |
| `full` | Full environment summary. Interactive prompts (environment type, live system, tenant/logging namespace when multiple exist). |
| `help` | None |

## Sub-commands

| Sub-command | Description |
|-------------|-------------|
| `cluster` | Kubernetes/OpenShift version and a **node summary table** (allocatable vs requested resources, usage, status, pods, runtime). |
| `full` | Full **BMC Helix Environment Summary** on the console and **`info.json`** (machine-readable, schema version in the file). |
| `help` | Prints this summary (same content as this file, built into the script). |

## `cluster` — node summary table

```bash
bash hitt.sh -m "info cluster"
```

Displays a table summarising the cluster resources.

Columns:

| Column | Meaning |
|--------|---------|
| **NODE_NAME** | Kubernetes node name. |
| **NODE_TYPE** | Role label (`control-plane`, `worker`, or comma-separated roles). |
| **ALLOCATABLE (CPU/MEM)** | Total allocatable CPU and memory on the node (`kubectl` `.status.allocatable`). |
| **ALLOCATED REQ (CPU/MEM)** | Sum of **container resource requests** for pods scheduled on the node (not limits). |
| **ACTUAL_USAGE** | CPU and memory **percentage** from `kubectl top nodes` when metrics are available; otherwise `Metrics N/A`. |
| **NODE_STATUS/CONDITIONS** | `Healthy`, `NotReady`, or pressure conditions (e.g. disk/memory pressure). |
| **PODS (RUN/BAD/CRASH)** | Running / Failed+Unknown / CrashLoopBackOff counts for pods on the node. |
| **OOM_KILLS** | Containers on the node terminated with **OOMKilled**. |
| **CONTAINER_RUNTIME** | Container runtime version from node status. |

**Notes:**

- Request totals can exceed allocatable on a node when many pods use small requests or when workloads rely on limits/bursts rather than requests.
- `kubectl top` requires a working **metrics-server** (or equivalent); absence of metrics does not stop the rest of the table.

## `full` — environment summary

```bash
bash hitt.sh -m "info full"
```

Collects cluster, ingress, Helix Platform, Helix Logging, Deployment Engine, and Helix Service Management details (when present).

## See also

- [README.md](README.md) — main HITT documentation
- [README-utility-mode.md](README-utility-mode.md) — `-u` helpers
- [README-fix-mode.md](README-fix-mode.md) — `-f` fixes
- Interactive use cases: https://bit.ly/hitthelp
