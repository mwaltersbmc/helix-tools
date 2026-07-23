# HITT Info Mode

**Info mode** (`-m info`) displays read-only summaries about a Helix environment. It is **under active development** — sub-commands and output may change between HITT builds.

**Quoting:** When `-m` takes multiple words, enclose the whole value in **double quotes** (e.g. `bash hitt.sh -m "info ingress"`). Unquoted forms such as `bash hitt.sh -m info ingress` are rejected or mis-parsed by the shell.

```bash
bash hitt.sh -m "info cluster"
bash hitt.sh -m "info helix"
bash hitt.sh -m "info ingress"
bash hitt.sh -m "info full"
bash hitt.sh -m "info help"
```

If you omit the sub-command (`bash hitt.sh -m info`), HITT defaults to **`full`**.

Built-in summary: `bash hitt.sh -m "info help"`

## Requirements

| Sub-command | Typical requirements |
|-------------|----------------------|
| `cluster` | Optional: **metrics-server** (or equivalent) for CPU/memory usage columns in the node table. |
| `helix` | No HITT configuration needed — scans the whole cluster. |
| `ingress` | **Helix Platform namespace** configured for HITT (reads **`INGRESS_CLASS`** from Platform configuration). |
| `full` | **HITT configuration** with Helix namespaces and settings, plus Deployment Engine login for the full environment summary. Interactive prompts (environment type, live system, tenant/logging namespace when multiple exist). |
| `help` | None |

## Sub-commands

| Sub-command | Description |
|-------------|-------------|
| `cluster` | Kubernetes/OpenShift version and a **node summary table** (allocatable vs requested resources, usage, status, pods, runtime). |
| `helix` | **Helix namespace scan** — lists namespaces that look like Helix Platform, Helix IS, containerized Deployment Engine, or Helix Logging, with **version** where HITT can read it from the cluster. |
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
| **ALLOCATABLE (CPU/MEM)** | Total allocatable CPU and memory on the node. |
| **ALLOCATED REQ (CPU/MEM)** | Sum of **container resource requests** for pods scheduled on the node (not limits). |
| **ACTUAL_USAGE** | CPU and memory **percentage** when node metrics are available; otherwise `Metrics N/A`. |
| **NODE_STATUS/CONDITIONS** | `Healthy`, `NotReady`, or pressure conditions (e.g. disk/memory pressure). |
| **PODS (RUN/BAD/CRASH)** | Running / Failed+Unknown / CrashLoopBackOff counts for pods on the node. |
| **OOM_KILLS** | Containers on the node terminated with **OOMKilled**. |
| **CONTAINER_RUNTIME** | Container runtime version from node status. |

**Notes:**

- Request totals can exceed allocatable on a node when many pods use small requests or when workloads rely on limits/bursts rather than requests.
- Usage percentages require a working **metrics-server** (or equivalent); absence of metrics does not stop the rest of the table.

## `helix` — Helix namespace scan

```bash
bash hitt.sh -m "info helix"
```

Scans **every namespace** in the cluster and prints Helix-related namespaces grouped by product. Use this when you need a quick map of where Helix is installed (for example on a shared cluster or before HITT is configured for your environment). It does **not** run the interactive prompts or full summary from **`info full`**.

Output is grouped into up to four sections. Each line is **namespace** and **version** (when HITT can read a version from the cluster):

| Section | What you see |
|---------|----------------|
| **Helix Platform** | Namespace and Helix Platform version |
| **Helix IS** | Namespace and Helix IS version |
| **Containerized Deployment Engine** | Namespace and Deployment Engine version |
| **Helix Logging** | Namespace name only |

Example output (format):

```text
Helix Platform
  my-hp-ns          26.1.00
Helix IS
  my-is-ns          26.1.00
Containerized Deployment Engine
  my-cde-ns         26.1.00
Helix Logging
  my-logging-ns
```

**Notes:**

- Sections with no matching namespaces are omitted.
- Version may show as **unknown** when HITT cannot read a version for that namespace.
- Standalone (non-containerized) Deployment Engine on the cluster host is **not** listed by this scan — use **`info full`** or Jenkins checks when the Deployment Engine is not running in the cluster.

## `ingress` — ingress controller summary

```bash
bash hitt.sh -m "info ingress"
```

Resolves the ingress controller workload for the **`INGRESS_CLASS`** value from Helix Platform configuration, then prints:

| Field | Meaning |
|-------|---------|
| **Ingress class (Helix config)** | `INGRESS_CLASS` from Helix Platform infra config (e.g. `nginx`). |
| **Workload type** | `deployment` or `daemonset` for the matched controller workload. |
| **Namespace** | Namespace where the controller workload runs. |
| **Workload** | Deployment or DaemonSet name. |
| **Image** | Container image for the ingress controller (not sidecar/application images). |

**Notes:**

- If no workload matches, the section may show `unknown` for some fields; check that the ingress class in Helix Platform configuration exists in the cluster.

## `full` — Helix environment summary

```bash
bash hitt.sh -m "info full"
# same as:
bash hitt.sh -m info
```

Collects and prints a **BMC Helix Environment Summary**, including:

- Client OS and tool versions (cluster and Helm clients)
- Cluster Kubernetes / OpenShift version
- **Node summary** (same table as `info cluster`)
- **Ingress controller** (same fields as `info ingress`)
- Helix Platform (namespace, version, tenants, services via tctl)
- Helix Logging (namespace, version)
- Deployment Engine (Jenkins URL, version, pipeline Helm version)
- Helix Service Management (when full-text search is present in the Helix IS namespace)

Also writes **`info.json`** in your HITT directory for support tooling (schema version in the file).

Expect **interactive** prompts: environment type (Dev/QA/Prod/…), whether the system is live, tenant selection when multiple exist, and Helix Logging namespace when more than one logging stack is found.

## See also

- [README.md](README.md) — main HITT documentation (brief **info ingress** note)
- [README-utility-mode.md](README-utility-mode.md) — `-u` helpers
- [README-fix-mode.md](README-fix-mode.md) — `-f` fixes
- Interactive use cases: https://bit.ly/hitthelp
