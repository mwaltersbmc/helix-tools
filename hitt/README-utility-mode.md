# HITT Utility Mode

**Utility mode** (`-u`) provides small helpers for everyday Helix tasks: licensing and database IDs, reading cluster secrets, checking pod health, validating certificates, and more.

When the command has spaces or multiple words, pass the whole thing in **double quotes**:

```bash
bash hitt.sh -u "get secret my-secret helix-is"
bash hitt.sh -u "check cert /path/to/cert.pem"
```

Built-in summary: `bash hitt.sh -u help` or `bash hitt.sh -h utility`

## Commands

| Command | Description |
|--------|-------------|
| `get dbid` | Shows the database ID (DBID) for your Helix IS system — used for licensing. |
| `get arlicense` | Shows the current **IS Server license type** (for example **AR Server** for a permanent license). |
| `get gsi list` | Lists every AR Server Info (GSI) constant as **name : id** pairs. |
| `get gsi GSI_ID` | Runs **Get Server Info** on the IS server for that GSI id and prints the current value. |
| `get jwt` | Prints a login token for Helix IS REST calls. Uses **hannah_admin** from the cluster unless you give another username. |
| `get secret` | Shows secret contents from the cluster. Args: **SECRETNAME** [**NAMESPACE**]. If you omit the namespace, HITT searches your Helix IS, Helix Platform, and Deployment Engine namespaces and asks you to choose when needed. |
| `get configmap` | Saves ConfigMap contents to a new folder in the current directory. With **`-v`**, lists key names only. Args: **CM_NAME** [**NAMESPACE**]. Namespace rules match **get secret**. |
| `get forms` | Finds AR forms whose name contains your keyword. Prints **Form name** and **Schema ID**. Args: **KEYWORD**. |
| `get fields` | Lists fields on a form. Args: **SCHEMAID** [**KEYWORD**] from **get forms**. |
| `sql` | Runs a custom AR SQL query and prints the result. Args: **SQL_QUERY** (put the full query inside the quoted `-u` string). |
| `gendbid` | Builds a DBID from **DB_TYPE**, **DATABASE_HOST_NAME**, and **AR_DB_NAME** before deployment. |
| `check arservers` | Lists each Helix IS platform pod with pod readiness and AR Server readiness. |
| `check liveness` | Runs the pod’s **liveness** health check and shows the response. Args: **PODNAME**. |
| `check readiness` | Same as **check liveness**, using the **readiness** check. Args: **PODNAME**. |
| `check cert` | Checks a PEM certificate file is valid and not expired, then tests HTTPS to your Helix Platform load balancer and Helix IS hostnames. Args: **/path/to/cert.pem** |
| `check pat` | Checks a Docker Hub username and personal access token can pull BMC Helix images. Omit both args to use registry credentials from Helix Platform when available. |
| `check rbac [hitt\|deploy\|all]` | Checks whether your cluster account has the permissions HITT or Helix deployment need. Default: **hitt**. |
| `imagels` | Lists tags for a container image repository. Requires **skopeo** and a registry login. Args: **IMAGE**. |
| `help` | Prints this summary (built into HITT). |

## Usage examples

```bash
# Current DBID from the running system
bash hitt.sh -u "get dbid"

# Current IS Server license type
bash hitt.sh -u "get arlicense"

# List AR Server Info (GSI) constant names and ids
bash hitt.sh -u "get gsi list"

# Get Server Info value for a GSI id (89 = AR_SERVER_INFO_SERVER_NAME)
bash hitt.sh -u "get gsi 89"

# Login token for hannah_admin
bash hitt.sh -u "get jwt"

# Login token for another user (password prompted if not given)
bash hitt.sh -u "get jwt myuser"

# Read a secret (name, then optional namespace)
bash hitt.sh -u "get secret ar-global-secret helix-is"
bash hitt.sh -u "get secret ar-global-secret"

# Export a ConfigMap (name, then optional namespace)
bash hitt.sh -u "get configmap my-configmap helix-is"
bash hitt.sh -u "get configmap my-configmap"

# List ConfigMap keys only — use global -v before -u
bash hitt.sh -v -u "get configmap my-configmap helix-is"

# Custom AR SQL
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'"

# Generate DBID before deployment (mssql | oracle | postgres)
bash hitt.sh -u "gendbid mssql my-db-server.acme.com arsystem"

# Helix IS platform pod status
bash hitt.sh -u "check arservers"

# Run a pod health check and show the response
bash hitt.sh -u "check readiness midtier-int-85486987d7-z22tt"
bash hitt.sh -u "check liveness platform-fts-0"

# Validate a certificate file before addcert or deployment
bash hitt.sh -u "check cert /path/to/cert.pem"

# Validate Docker Hub credentials
bash hitt.sh -u "check pat"
bash hitt.sh -u "check pat mydockerhubuser"
bash hitt.sh -u "check pat mydockerhubuser dckr_pat_xxxxxxxx"

# List image tags on Docker Hub
bash hitt.sh -u "imagels ars"

# List tags on a private registry (log in with skopeo first)
skopeo login harbor.example.com
bash hitt.sh -u "imagels harbor.example.com/bmchelix/ars"

# Check cluster permissions
bash hitt.sh -u "check rbac"
bash hitt.sh -u "check rbac hitt"
bash hitt.sh -u "check rbac deploy"
bash hitt.sh -u "check rbac all"

bash hitt.sh -u help
```

## `get dbid`

Shows the current DBID from your running Helix IS system.

## `get arlicense`

Shows the current **IS Server license type**. A permanent production license is usually **AR Server**. Other types may mean you still need to apply a full license — see fix mode **arlicense** in [README-fix-mode.md](README-fix-mode.md).

## `get gsi`

AR **GSI** (Global Server Info) settings are numbered constants (`AR_SERVER_INFO_*` in the AR API). HITT embeds the full name-to-id map.

- **`get gsi list`** — prints every known constant as `name : id` (sorted by id).
- **`get gsi GSI_ID`** — runs **Get Server Info** against your Helix IS server for that numeric id and prints the current value.

```bash
bash hitt.sh -u "get gsi list"
bash hitt.sh -u "get gsi 89"
```

Use **list** first when you know the setting name but not the id (for example **AR_SERVER_INFO_SERVER_NAME** is id **89**).

## `get jwt`

- With no username: uses **hannah_admin** and reads the password from the cluster.
- With a username: uses that user. Give the password as the next argument, or HITT prompts you.

## `get secret SECRETNAME [NAMESPACE]`

Shows the named secret from the cluster. Readable values print on screen; other values save as files in the current directory.

If you omit **NAMESPACE**, HITT looks in your Helix IS, Helix Platform, and Deployment Engine namespaces. It uses the namespace automatically when the secret exists in only one. When it exists in more than one, you choose from a menu.

## `get configmap CM_NAME [NAMESPACE]`

Exports the named ConfigMap to a new folder under the current directory (named after the ConfigMap). With **`-v`**, HITT lists key names only and does not create files.

Optional **NAMESPACE** follows the same rules as **get secret**.

## Finding forms (`get forms KEYWORD`)

Use this when you know part of a form name and need the full name or **Schema ID** for **get fields**.

```bash
bash hitt.sh -u "get forms Login"
bash hitt.sh -u "get forms AR System Metadata"
```

Use double quotes when the keyword contains spaces.

## Finding fields (`get fields SCHEMAID [KEYWORD]`)

Use after **get forms** gave you a **Schema ID**.

- **SCHEMAID only** — lists every field on that form.
- **SCHEMAID and KEYWORD** — lists fields whose name contains the keyword.

```bash
bash hitt.sh -u "get fields 163"
bash hitt.sh -u "get fields 163 Login"
```

## Custom AR SQL (`sql SQL_QUERY`)

Use **get forms** or **get fields** for simple lookups. Use **sql** when you need your own query.

Put the whole command in double quotes, including the word `sql` and the full query. Use square brackets around AR table and column names.

```bash
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'"
```

Field names must be database names, not display labels — use **get forms** and **get fields** to confirm them.

## `gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME`

Builds a DBID string. **DB_TYPE** is `mssql`, `oracle`, or `postgres`.

## `check arservers`

Lists each Helix IS platform pod and shows:

| Column | Meaning |
|--------|---------|
| **Name** | Pod name |
| **K8s Status** | Whether the platform pod is ready |
| **AR Status** | Whether the AR Server inside the pod is ready (**skipped** when the pod itself is not ready yet) |

This is the same check HITT runs in **post-is** and **upgrade-is** mode.

```bash
bash hitt.sh -u "check arservers"
```

## `check liveness PODNAME` / `check readiness PODNAME`

Runs the same health check configured on the pod and prints the response — useful when a pod stays not ready and you want to see what the check returns.

HITT finds **PODNAME** in your Helix IS, Helix Platform, or Deployment Engine namespaces. You choose when the name appears in more than one place, or when the pod has more than one container.

The check runs from inside the cluster. HITT shows the URL, then the response. JSON responses are formatted for readability.

```bash
bash hitt.sh -u "check readiness midtier-int-85486987d7-z22tt"
bash hitt.sh -u "check liveness platform-fts-0"
```

## `check cert /path/to/cert.pem`

Checks a PEM file before you add it with **addcert** (fix mode) or deploy it to the cluster.

For each certificate in the file, HITT confirms it is valid and **not expired** (warns if expiry is within four weeks). Then it tests HTTPS connections to:

- Your Helix Platform load balancer hostname
- Your Helix IS service hostnames (midtier and related aliases for your deployment)

Each connection must complete a secure TLS handshake. HITT does not check the web page content.

```bash
bash hitt.sh -u "check cert /path/to/cert.pem"
```

## `check pat [USERNAME] [PAT]`

Verifies a Docker Hub username and personal access token can pull the **bmchelix** repository.

If you omit both arguments, HITT offers credentials stored in Helix Platform when it finds them. Otherwise you are prompted.

If you give **USERNAME** only, HITT prompts for the token (input is hidden).

## `imagels IMAGE`

Lists tags for a container image using **skopeo**. Install skopeo and log in to the registry first — see [skopeo.org](https://skopeo.org/#download).

| Form | Resolves to |
|------|-------------|
| Short name (no `/`) | `docker.io/bmchelix/IMAGE` — for example `ars` |
| Full path (contains `/`) | Used as-is |

```bash
bash hitt.sh -u imagels ars
bash hitt.sh -u "imagels my-registry.example.com/bmchelix/ars"
```

## `check rbac [hitt|deploy|all]`

Checks whether the account HITT uses has enough access in the cluster.

| Profile | What it checks |
|--------|----------------|
| **hitt** (default) | Read access HITT needs for triage, plus permissions for fix-mode changes (certificates, Support Assistant role, and similar). |
| **deploy** | Permissions needed to install or upgrade Helix in your namespaces. See [Deployment Engine RBAC](https://docs.helixops.ai/bin/Service-Management/On-Premises-Deployment/BMC-Helix-Service-Management-Deployment/brid26201/Installing/Preparing-for-installation/Setting-up-the-BMC-Deployment-Engine/). |
| **all** | Both profiles combined. |

Checks use your configured Helix Platform, Helix IS, Deployment Engine, and Helix Logging namespaces.

## See also

- [README-fix-mode.md](README-fix-mode.md) — **`-f` fix mode** (cacerts, Jenkins, license apply, and more)
- [README-pipeline-mode.md](README-pipeline-mode.md) — **`-k` pipeline mode**
- [README-info-mode.md](README-info-mode.md) — **`-i` info mode**
- Step-by-step use cases: https://bit.ly/hitthelp
