# HITT Info Mode

**Info mode** (`-m info`) displays read-only summaries about a Helix environment. It is **under active development** — sub-commands and output may change between HITT builds.

When `-m` takes multiple words, enclose the whole value in **double quotes**:

```bash
bash hitt.sh -m "info cluster"
bash hitt.sh -m "info node <node-name>"
bash hitt.sh -m "info helix"
bash hitt.sh -m "info ingress"
bash hitt.sh -m "info dbversions"
bash hitt.sh -m "info full"
bash hitt.sh -m "info help"
```

If you omit the sub-command (`bash hitt.sh -m info`), HITT defaults to **`full`**.

Built-in summary: `bash hitt.sh -m "info help"`

## Sub-commands

| Sub-command | Description |
|-------------|-------------|
| `cluster` | Kubernetes / OpenShift version and a **node summary table** (allocatable vs requested resources, usage, status, pods, runtime). |
| `node` | **Per-pod resource table** for one named node (requests, limits, current usage, ephemeral storage). |
| `helix` | **Helix namespace scan** — lists namespaces that look like Helix Platform, Helix IS, containerized Deployment Engine, or Helix Logging, with **version** where HITT can read it. |
| `ingress` | **Ingress controller** details for the Helix **INGRESS_CLASS**: workload type, namespace, workload name, and container image. |
| `dbversion` / `dbversions` | **Helix IS database versions** — tab-separated release and expected database version used by HITT checks. |
| `full` | Full **BMC Helix Environment Summary** on the console and **`info.json`** (machine-readable, schema version in the file). |
| `help` | Prints this summary (built into HITT). |

## `cluster` — node summary table

```bash
bash hitt.sh -m "info cluster"
```

Displays a table summarising cluster node resources.

| Column | Meaning |
|--------|---------|
| **NODE_NAME** | Node name. |
| **NODE_TYPE** | Role label (`control-plane`, `worker`, or comma-separated roles). |
| **ALLOCATABLE (CPU/MEM)** | Total allocatable CPU (**cores**) and memory (**Gi**) on the node. |
| **ALLOCATED REQ (CPU/MEM)** | Sum of **container resource requests** for **Running** pods on the node (**cores** / **Gi**; not limits). Parentheses show **remaining allocatable memory** (Gi). |
| **EPHEMERAL STORAGE (TOTAL/USED)** | **Total** and **used** ephemeral storage on the node filesystem (Gi). Shows `Stats N/A` when storage stats cannot be read (often missing permission to read node storage stats). |
| **ACTUAL_USAGE** | CPU and memory **percentage** when node metrics are available; otherwise `Metrics N/A`. |
| **NODE_STATUS/CONDITIONS** | `Healthy`, `NotReady`, or pressure conditions (e.g. disk/memory pressure). |
| **PODS (RUN/BAD/CRASH)** | Running / Failed+Unknown / CrashLoopBackOff counts for pods on the node. |
| **OOM_KILLS** | Containers on the node terminated with **OOMKilled**. |
| **CONTAINER_RUNTIME** | Container runtime version from node status. |

**Notes:**

- Request totals can exceed allocatable on a node when many pods use small requests or when workloads rely on limits/bursts rather than requests. Remaining memory in parentheses can be negative when requests exceed allocatable memory.
- Ephemeral storage **total/used** reflects actual disk use on the node (logs, emptyDir, container layers, images). It is **not** the same as pod ephemeral-storage resource requests, which most pods do not set.
- Usage percentages need **metrics-server** (or equivalent) in the cluster; absence of metrics does not stop the rest of the table.

## `node` — per-pod resource usage

```bash
bash hitt.sh -m "info node"
bash hitt.sh -m "info node vs-ak8s02-hlxcussp-cl2-04"
```

If you omit the node name, HITT lists cluster nodes and prompts you to **select one** interactively.

Lists every pod scheduled on the named node, sorted by namespace and name.

| Column | Meaning |
|--------|---------|
| **POD_NAME** | Pod namespace and name (`namespace/pod`). |
| **REQUESTS (CPU/MEM)** | Sum of **container resource requests** (**cores** / **Gi**). |
| **LIMITS (CPU/MEM)** | Sum of **container resource limits** (**cores** / **Gi**); `0` / `0Gi` when unset. |
| **CURRENT USAGE (CPU/MEM)** | Live CPU and memory from **metrics-server** when available; otherwise `Metrics N/A`. |
| **EPHEMERAL STORAGE** | Ephemeral storage **used** by the pod (Gi); `N/A` when stats omit the pod, `Stats N/A` when storage stats cannot be read. |

**Notes:**

- Ephemeral storage is omitted from node stats for some pods; those rows show `N/A`.
- **CURRENT USAGE** is only reported for Running pods that metrics-server tracks.
- Per-pod usage and ephemeral storage columns need **metrics-server** (or equivalent); node storage stats may need extra node read permissions.

## `helix` — Helix namespace scan

```bash
bash hitt.sh -m "info helix"
```

Scans **every namespace** in the cluster and prints Helix-related namespaces grouped by product. Use this for a quick map of where Helix is installed (for example on a shared cluster). It does **not** run the interactive prompts or full summary from **`info full`**.

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
- Standalone (non-containerized) Deployment Engine on the cluster host is **not** listed — use **`info full`** when the Deployment Engine is not running in the cluster.

## `ingress` — ingress controller summary

```bash
bash hitt.sh -m "info ingress"
```

Resolves the ingress controller workload for the **INGRESS_CLASS** value from Helix Platform configuration, then prints:

| Field | Meaning |
|-------|---------|
| **Ingress class (Helix config)** | **INGRESS_CLASS** from Helix Platform configuration (e.g. `nginx`). |
| **Workload type** | `deployment` or `daemonset` for the matched controller workload. |
| **Namespace** | Namespace where the controller workload runs. |
| **Workload** | Controller workload name. |
| **Image** | Container image for the ingress controller (not sidecar or application images). |

**Notes:**

- Helix Platform must be deployed so HITT can read **INGRESS_CLASS**.
- If no workload matches, some fields may show `unknown` — check that the ingress class in Helix Platform configuration exists in the cluster.

## `dbversion` / `dbversions` — Helix IS database version reference

```bash
bash hitt.sh -m "info dbversions"
# or
bash hitt.sh -m "info dbversion"
```

Prints a tab-separated table of Helix IS releases and the **expected database version** HITT uses when validating your database during deployment checks:

```text
IS_VERSION      IS_DB_VERSION
21.x            199
22.x            200
23.x            201
23.3.04         203
25.1.01         203
...
```

**Notes:**

- Rows use **21.x**, **22.x**, and **23.x** for all releases in those major versions except where a specific release is listed (for example **23.3.04**).
- Only Helix IS releases known to HITT are listed; if your release is missing, update HITT or open a support case.

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
- Helix Platform (namespace, version, tenants, services)
- Helix Logging (namespace, version)
- Deployment Engine (Jenkins URL, version, pipeline Helm version)
- Helix Service Management (when full-text search is present in the Helix IS namespace)

Also writes **`info.json`** in your HITT directory for support tooling (schema version in the file).

Expect **interactive** prompts: environment type (Dev/QA/Prod/…), whether the system is live, tenant selection when multiple exist, and Helix Logging namespace when more than one logging stack is found.

## See also

- [README.md](README.md) — main HITT documentation
- [README-utility-mode.md](README-utility-mode.md) — `-u` helpers
- [README-fix-mode.md](README-fix-mode.md) — `-f` fixes
- Interactive use cases: https://bit.ly/hitthelp
