# HITT Info Mode

**Info mode** (`-m info`) displays read-only summaries about a Helix environment. It is **under active development** — sub-commands and output may change between HITT builds.

**Quoting:** When `-m` takes multiple words, enclose the whole value in **double quotes** (e.g. `bash hitt.sh -m "info ingress"`). Unquoted forms such as `bash hitt.sh -m info ingress` are rejected or mis-parsed by the shell.

```bash
bash hitt.sh -m "info cluster"
bash hitt.sh -m "info ingress"
bash hitt.sh -m "info full"
bash hitt.sh -m "info help"
```

If you omit the sub-command (`bash hitt.sh -m info`), HITT defaults to **`full`**.

Built-in summary: `bash hitt.sh -m "info help"`

## Requirements

| Sub-command | Typical requirements |
|-------------|----------------------|
| `cluster` | Valid **kubeconfig** and **kubectl** access to list nodes and metrics (`kubectl top nodes` when the metrics server is available). **Does not** require `hitt.conf`. |
| `ingress` | **hitt.conf** with Helix Platform namespace (reads **`INGRESS_CLASS`** from Platform config). **kubectl** access to list IngressClasses and Deployments/DaemonSets cluster-wide. |
| `full` | **hitt.conf** with Helix namespaces and settings, plus cluster/Jenkins/RSSO access for the full environment summary. Interactive prompts (environment type, live system, tenant/logging namespace when multiple exist). |
| `help` | None |

## Sub-commands

| Sub-command | Description |
|-------------|-------------|
| `cluster` | Kubernetes/OpenShift version and a **node summary table** (allocatable vs requested resources, usage, status, pods, runtime). |
| `ingress` | **Ingress controller** details for the Helix **`INGRESS_CLASS`**: workload type, namespace, workload name, and container image. |
| `full` | Full **BMC Helix Environment Summary** on the console and **`info.json`** (machine-readable, schema version in the file). |
| `help` | Prints this summary (same content as this file, built into the script). |

## `cluster` — node summary table

```bash
bash hitt.sh -m "info cluster"
```

Displays a table summarising cluster node resources.

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

## `ingress` — ingress controller summary

```bash
bash hitt.sh -m "info ingress"
```

Resolves the ingress controller workload for the **`INGRESS_CLASS`** value from Helix Platform configuration (`hitt.conf` / Platform configMap), then prints:

| Field | Meaning |
|-------|---------|
| **Ingress class (Helix config)** | `INGRESS_CLASS` from Helix Platform infra config (e.g. `nginx`). |
| **Workload type** | `deployment` or `daemonset` for the matched controller workload. |
| **Namespace** | Namespace where the controller workload runs. |
| **Workload** | Deployment or DaemonSet name. |
| **Image** | Container image for the ingress controller (not sidecar/application images). |

**Notes:**

- If no workload matches, the section may show `unknown` for some fields; check `kubectl get ingressclasses` and that the class in config exists in the cluster.

## `full` — Helix environment summary

```bash
bash hitt.sh -m "info full"
# same as:
bash hitt.sh -m info
```

Collects and prints a **BMC Helix Environment Summary**, including:

- Client OS and tool versions (kubectl, Helm)
- Cluster Kubernetes / OpenShift version
- **Node summary** (same table as `info cluster`)
- **Ingress controller** (same fields as `info ingress`)
- Helix Platform (namespace, version, tenants, services via tctl)
- Helix Logging (namespace, version)
- Deployment Engine (Jenkins URL, version, pipeline Helm version)
- Helix Service Management (when `platform-fts` is present in the IS namespace)

Also writes **`info.json`** in the current directory for support tooling (schema version in the file).

Expect **interactive** prompts: environment type (Dev/QA/Prod/…), whether the system is live, tenant selection when multiple exist, and Helix Logging namespace when more than one EFK stack is found.

## See also

- [README.md](README.md) — main HITT documentation (brief **info ingress** note)
- [README-utility-mode.md](README-utility-mode.md) — `-u` helpers
- [README-fix-mode.md](README-fix-mode.md) — `-f` fixes
- Interactive use cases: https://bit.ly/hitthelp
