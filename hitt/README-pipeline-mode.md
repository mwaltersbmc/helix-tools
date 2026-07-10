# HITT Pipeline Mode

Pipeline mode helps you work with **HELIX_ONPREM_DEPLOYMENT** on the Deployment Engine (Jenkins). HITT uses the Jenkins address and login from your **hitt.conf** file.

You can:

- **Save** parameter values from an existing job run (**get**)
- **Send** saved values to start a new job run (**build**) — useful when moving to a different Deployment Engine
- **Fill in** many values automatically from Helix Platform (**kickstart**) — useful for a new deployment when Platform is already installed

When a command has more than one word after **`-k`**, put the whole thing in **double quotes**:

```bash
bash hitt.sh -k "get lastsuccessful"
bash hitt.sh -k "build values.json"
bash hitt.sh -k kickstart
bash hitt.sh -k help
```

## What you need first

| Command | What you need |
|---------|----------------|
| **get** | **hitt.conf** with Deployment Engine URL and login. |
| **build** | The same as **get**, plus a settings file from **get** (or one you edited by hand). |
| **kickstart** | **hitt.conf**, access to the cluster, and Helix Platform already deployed so HITT can read namespace, domain, registry, and sign-on settings. Same for **get kickstart**. |

HITT must be able to log in to the Deployment Engine for all three commands.

## Commands at a glance

| Command | What it does |
|---------|----------------|
| **get** | Shows or saves the job’s parameter values (including **get kickstart** to preview kickstart fills). |
| **build** | Starts a new **HELIX_ONPREM_DEPLOYMENT** run using your saved settings file. |
| **kickstart** | Looks up values from your environment, then starts a new run with those values filled in. |
| **help** | Shows a short summary of pipeline mode (same as this guide, built into the script). |

**Related:** To read the log from the latest run of a job, use **`-o`** (not pipeline mode):

```bash
bash hitt.sh -o helix_onprem_deployment
```

---

## get — save parameter values

```bash
bash hitt.sh -k "get <defaults|last|lastsuccessful|kickstart|N> [filename]"
```

| You ask for | You get |
|-------------|---------|
| **defaults** | The job’s default values on the Deployment Engine. |
| **last** | Values from the most recent run (pass or fail). |
| **lastsuccessful** | Values from the last run that completed successfully. |
| **kickstart** | Job defaults with kickstart-discovered values filled in (see below). Requires **hitt.conf**, cluster access, and Helix Platform deployed — same as **kickstart** build. |
| **N** | Values from run number **N** (for example **7**). |

If you do not give a file name, the settings appear on screen. If you add a file name, they are saved to that file (for example **values.json**).

Blank fields and layout-only entries are left out of the saved file.

### Password parameters

By default, any parameter whose name contains **PASSWORD** is shown as **`***REDACTED***`** in **get** output (on screen and in saved files). Use **`-p`** to include plain values:

```bash
bash hitt.sh -k "get lastsuccessful"                    # passwords redacted
bash hitt.sh -p -k "get lastsuccessful values.json"     # plain passwords (for build)
```

Use **`-p`** only on a trusted host and protect saved files. If you save with redacted passwords and run **build**, those placeholders are sent to Jenkins — export with **`-p`** when the file is meant for **build** or another Deployment Engine.

**Examples:**

```bash
bash hitt.sh -k "get defaults"
bash hitt.sh -k "get lastsuccessful"
bash hitt.sh -k "get kickstart"
bash hitt.sh -k "get kickstart kickstart-preview.json"
bash hitt.sh -k "get 7 values.json"
```

### get kickstart — preview values without starting a run

```bash
bash hitt.sh -k "get kickstart"
bash hitt.sh -p -k "get kickstart kickstart-preview.json"
```

Use this to see what **kickstart** would fill in before you queue a run. HITT loads the job’s default parameters from the Deployment Engine, reads Helix Platform and cluster settings (same discovery as **kickstart**), and overwrites matching fields in the output.

File upload parameters, **INPUT_CONFIG_METHOD**, and layout-only entries are omitted. Every checkbox under **Pipelines** is set to **false**, matching what **build** and **kickstart** apply when queuing a run.

### Save, edit, and build

You can save **get kickstart** output to a file, add any values HITT does not discover (database connection, extra passwords, which **Pipelines** stages to run, and so on), then start a Jenkins run with **build**:

```bash
bash hitt.sh -p -k "get kickstart deploy-params.json"   # -p so passwords are usable in build
# Edit deploy-params.json — add DB settings, set pipeline checkboxes to true where needed, etc.
bash hitt.sh -k "build deploy-params.json"
```

Then open **HELIX_ONPREM_DEPLOYMENT** on the Deployment Engine, **Rebuild** the last run, attach any **file** parameters (certificates, config uploads), and confirm the form before a real deployment.

This workflow gives you the same pre-fill as **kickstart**, but you control the JSON on disk before anything is queued. Use **`-p`** when saving the file if you intend to run **build** with it; redacted `***REDACTED***` placeholders are not valid for Jenkins.

---

## build — start a run from a saved settings file

```bash
bash hitt.sh -k "build values.json"
```

Use a settings file you created with **get** (including **get kickstart**), or edited yourself. HITT sends those values to **HELIX_ONPREM_DEPLOYMENT** and starts a new run.

A typical path for a new deployment when Helix Platform is already installed:

1. **`bash hitt.sh -p -k "get kickstart deploy-params.json"`** — known values from Platform and **hitt.conf** (use **`-p`** if the file will be used with **build**).
2. **Edit** `deploy-params.json` — database details, enable the **Pipelines** checkboxes you need, and any other missing fields.
3. **`bash hitt.sh -k "build deploy-params.json"`** — queue the run.
4. **Rebuild** in the Deployment Engine and attach file uploads that HITT cannot send.

### What to expect

1. Run **build** (or **kickstart**).
2. Open **HELIX_ONPREM_DEPLOYMENT** on the Deployment Engine.
3. Use **Rebuild** on the last run and check every parameter. Add anything that is still missing — database details, passwords, certificate files, and which pipelines to run.

The first run often **fails on purpose** if required fields are still empty. That is normal. You finish the form in the Deployment Engine, then rebuild when you are ready for a real deployment.

### What HITT does for you when you use build or kickstart

- **File attachments** (config files, certificates, and similar) are not sent from HITT. You attach those in the Deployment Engine when you rebuild.
- Every checkbox under the **Pipelines** section is turned **off** unless you already set it in your settings file. That stops a full deployment from starting before you review the job.
- Values that do not apply to your Deployment Engine version are adjusted or removed automatically.

When the request succeeds, HITT tells you to open the job and rebuild so you can review and complete the parameters.

---

## kickstart — fill values from Helix Platform

```bash
bash hitt.sh -k kickstart
```

Use this for a **new** deployment when Helix Platform is already in the cluster. HITT reads **hitt.conf** and the cluster, fills in every value it can find, and starts a **HELIX_ONPREM_DEPLOYMENT** run — the same follow-up steps as **build** above.

To preview those fills without starting a run, use **`bash hitt.sh -k "get kickstart"`** (see [get kickstart](#get-kickstart--preview-values-without-starting-a-run) above). To save, edit, and then queue a run, use **get kickstart** → edit JSON → **build** (documented in the same section).

HITT will **not** fill in everything. Database settings, some passwords, file uploads, and deployment choices are still yours to complete in the Deployment Engine after you rebuild.

### Where kickstart gets information

- OpenShift vs Kubernetes (restricted security context when on OpenShift)
- Cluster connection name
- Names and customer settings from **hitt.conf**
- Helix Platform namespace, domain, ingress, registry, and company name
- Sign-on (RSSO) URL and admin login
- Tenant name
- Whether Helix Logging is installed (fluent-bit sidecar)
- Search (FTS) connection details from Platform / logging

### Jenkins parameters kickstart may set for you

These are the fields you should see already filled when you rebuild the job (names match the Deployment Engine form):

| Parameter | Filled from |
|-----------|-------------|
| **OS_RESTRICTED_SCC** | Cluster type (OpenShift) |
| **CLUSTER_CONTEXT** | Your cluster connection |
| **IS_NAMESPACE**, **CUSTOMER_SERVICE**, **ENVIRONMENT** | **hitt.conf** |
| **INGRESS_CLASS** | Helix Platform |
| **CLUSTER_DOMAIN**, **APPLICATION_PARENT_DOMAIN** | Helix domain |
| **SIDECAR_FLUENTBIT** | Helix Logging present |
| **HARBOR_REGISTRY_HOST**, **IMAGE_REGISTRY_USERNAME**, **IMAGE_REGISTRY_PASSWORD** | Platform image registry |
| **IMAGESECRET_NAME** | Default registry secret name |
| **FTS_ELASTICSEARCH_***(hostname, port, user, password, secure) | Platform / logging |
| **RSSO_URL**, **RSSO_ADMIN_USER**, **RSSO_ADMIN_PASSWORD** | Platform sign-on |
| **TENANT_DOMAIN** | Platform tenant |
| **HELIX_PLATFORM_NAMESPACE**, **HELIX_PLATFORM_CUSTOMER_NAME** | Platform namespace and company |

Checkboxes under **Pipelines** are left off by HITT so you choose when to run each stage.

---

## Moving settings to another Deployment Engine

Example: you used a standalone Deployment Engine and now use the in-cluster Jenkins from a newer release.

1. On the **old** system: `bash hitt.sh -p -k "get lastsuccessful values.json"`
2. Copy **values.json** to the new system. Set up **hitt.conf** for the new Deployment Engine (or use **`-c`** to point at another config file).
3. On the **new** system: `bash hitt.sh -k "build values.json"`
4. Rebuild **HELIX_ONPREM_DEPLOYMENT** in the web UI and update any values that differ on the new environment.

---

## More help

- [Main HITT guide](README.md) — setup, **hitt.conf**, other modes
- [Fix mode](README-fix-mode.md) — fix Deployment Engine libraries, credentials, and related issues
- Step-by-step use cases: https://bit.ly/hitthelp
