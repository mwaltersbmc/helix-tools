# HITT Utility Mode

**HITT** utility mode provides small helpers for Helix deployments (DBID/JWT, IS license type, secret decode, ConfigMap export, AR form/field search and custom SQL queries, generated DBID, Docker Hub PAT check, container image tag listing).

Utility commands are invoked with **`-u`**. When the command has spaces or multiple words, pass the whole thing in **double quotes**.

## Commands

| Command | Description |
|--------|-------------|
| `get dbid` | Displays the database ID (DBID) for the system (used for licensing). |
| `get arlicense` | Displays the current **IS Server license type** (for example **AR Server** for a permanent license, or a temporary type before a full license is applied). |
| `get jwt` | Prints an AR-JWT for the IS REST API. Defaults to `hannah_admin` using credentials from the cluster; optional username/password. |
| `get secret` | Decodes and displays secret data from the cluster. Binary keys are written to files; remaining keys are printed. Args: **SECRETNAME** [**NAMESPACE**]. If namespace is omitted, searches your Helix IS namespace, then Helix Platform namespace, then Deployment Engine namespace (from your HITT settings); prompts if more than one match (use explicit namespace with `-q` / automation). |
| `get configmap` | Exports ConfigMap `.data` and `.binaryData` keys to files under a new directory (named after the ConfigMap, with a numeric suffix if that name already exists). With **`-v`**, lists key names only (no files). Args: **CM_NAME** [**NAMESPACE**]. Optional namespace uses the same search and prompt rules as `get secret`. |
| `get forms` | Searches AR forms whose name contains your keyword; prints **Form name** and **Schema ID**. Args: **KEYWORD**. |
| `get fields` | Lists fields on one form using its **Schema ID** from `get forms`. Args: **SCHEMAID** [**KEYWORD**]. Omit the keyword to list all fields; add a keyword to filter by field name. |
| `sql` | Runs a custom AR SQL query via the IS REST API and prints the full JSON response. Args: **SQL_QUERY** (put the entire query inside the quoted `-u` string). |
| `gendbid` | Generates a database ID (DBID) from **DB_TYPE**, **DATABASE_HOST_NAME**, and **AR_DB_NAME**. |
| `checkpat` | Validates a Docker Hub **USERNAME** and **Personal Access Token** by requesting a registry token and checking pull scope for a private BMC Helix repository under that user. Omit both args to offer credentials from the **bmc-dtrhub** secret in your Helix Platform namespace; omit **PAT** only to be prompted (hidden). |
| `imagels` | Lists tags available in a container image repository using **skopeo**. Args: **IMAGE** — either an image name, for example `ars` in which case `docker.io/bmchelix/` is assumed, or a full **registry/host/path/repository/image** (for other registries). Requires **skopeo** and a prior **`skopeo login`** to the registry host. |
| `checkrbac [hitt\|deploy\|all]` | Validates Kubernetes RBAC for the account HITT uses. **hitt** (default): triage/read checks plus fix-mode writes (tctl, cacerts, SAT). **deploy**: shared reads plus install/upgrade permissions (Helix Platform, IS, logging, and Deployment Engine namespaces from your HITT settings). **all**: union of both. |
| `help` | Prints the same summary as this file (built into the script). |

## Usage

```bash
# Current DBID from the running system
bash hitt.sh -u "get dbid"

# Current IS Server license type
bash hitt.sh -u "get arlicense"

# JWT for hannah_admin (cluster credentials)
bash hitt.sh -u "get jwt"

# JWT for another user (password prompted if not given)
bash hitt.sh -u "get jwt myuser"

# Decode a secret (secret name, then optional namespace — omit namespace to search your configured Helix namespaces)
bash hitt.sh -u "get secret ar-global-secret helix-is"
bash hitt.sh -u "get secret ar-global-secret"

# Export a ConfigMap (name, then optional namespace) — creates a directory in the current working directory
bash hitt.sh -u "get configmap my-configmap helix-is"
bash hitt.sh -u "get configmap my-configmap"

# List ConfigMap keys only (no export) — use global -v before -u
bash hitt.sh -v -u "get configmap my-configmap helix-is"

# Custom AR SQL (raw JSON on stdout)
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'"
bash hitt.sh -u "sql select [Login Name],[Full Name] from [User] where [Login Name] = 'hannah_admin'"

# Generate DBID before deployment / license (mssql | oracle | postgres)
bash hitt.sh -u "gendbid mssql my-db-server.acme.com arsystem"

# Validate Docker Hub PAT (omit both args to use HP namespace secret, or USERNAME only / PAT prompted)
bash hitt.sh -u checkpat
bash hitt.sh -u "checkpat mydockerhubuser"
bash hitt.sh -u "checkpat mydockerhubuser dckr_pat_xxxxxxxx"

# List tags for a BMC Helix image on Docker Hub (repository docker.io/bmchelix/platform-core)
bash hitt.sh -u "imagels ars"

# List tags on a private registry (Harbor example — log in with skopeo first)
skopeo login harbor.example.com
bash hitt.sh -u "imagels harbor.example.com/bmchelix/ars"

# Kubernetes RBAC audit (requires Helix namespaces in your HITT configuration)
bash hitt.sh -u checkrbac
bash hitt.sh -u "checkrbac hitt"
bash hitt.sh -u "checkrbac deploy"
bash hitt.sh -u "checkrbac all"

bash hitt.sh -u help
```

### `get dbid`

Uses your **HITT configuration** and IS REST to print the current DBID.

### `get arlicense`

Uses your **HITT configuration** and IS REST to print the current **IS Server license type**. A permanent production license is usually shown as **AR Server**; temporary or evaluation types indicate you may still need to apply a full license (see fix mode **arlicense** in [README-fix-mode.md](README-fix-mode.md)).

### `get jwt`

- With no username: uses **hannah_admin** and resolves password from the cluster (same path as normal HITT checks).
- With a username: uses that user; password is taken from the second argument if present, otherwise prompted.

### `get secret SECRETNAME [NAMESPACE]`

Reads the named secret from the cluster, base64-decodes its data entries, and:

- Prints `key: value` lines for values that look printable (ASCII-safe).
- For other keys, writes decoded bytes to uniquely named files in the current directory and prints a short log line.

If **NAMESPACE** is omitted, HITT looks for the secret in your Helix IS namespace, then Helix Platform namespace, then Deployment Engine namespace (from your HITT settings, skipping blanks and duplicates). If it exists in exactly one of those namespaces, that namespace is used. If it exists in more than one, you are prompted to choose (same mechanism as other HITT menus). If it is not found in any of the three, the command fails and you should pass **NAMESPACE** on the command line.

### `get configmap CM_NAME [NAMESPACE]`

Reads the named ConfigMap from the cluster. If the ConfigMap is missing, the command fails with an error.

Otherwise it creates a directory under the current working directory named **CM_NAME** (or **CM_NAME.1**, **CM_NAME.2**, … if that name already exists). Each key in `.data` is written as a UTF-8 text file named after the key; each key in `.binaryData` is base64-decoded and written as raw bytes to a file named after the key. Keys containing `/` or `..` are rejected. A short summary line is printed with counts and the directory path.

Run with **`-v`** (verbose) to **list only** the names of keys under `.data` and `.binaryData`; no directory is created and nothing is written to disk.

Optional **NAMESPACE** uses the same Helix IS → Helix Platform → Deployment Engine namespace discovery, interactive choice when ambiguous.

### Finding forms (`get forms KEYWORD`)

Use this when you know part of a form name but need the full name or its **Schema ID** (a number HITT uses in the next step).

1. Run from your HITT directory.
2. Use a keyword that appears in the form name (for example `Login` or `AR System Metadata`).
3. Read the table: first column is the form name, second is **Schema ID**.

Example:

```bash
bash hitt.sh -u "get forms Login"
bash hitt.sh -u "get forms AR System Metadata"
```

If the keyword has spaces, keep the entire utility command inside double quotes (see second example above).

### Finding fields on a form (`get fields SCHEMAID [KEYWORD]`)

Use this after you have a **Schema ID** from `get forms`.

- **SCHEMAID only** — lists every field on that form.
- **SCHEMAID and KEYWORD** — lists only fields whose name contains the keyword.

Example:

```bash
bash hitt.sh -u "get fields 163"
bash hitt.sh -u "get fields 163 Login"
```

### Running custom AR SQL (`sql SQL_QUERY`)

Use **`get forms`** or **`get fields`** for everyday lookups. Use **`sql`** when you need your own query against AR metadata tables.

1. Run from your HITT directory.
2. Put the **whole** command in double quotes, including the word `sql` and the full SQL text.
3. Use **square brackets** around table and column names (AR style), for example `[name]` and `[AR System Metadata: arschema]`.
4. HITT prints **JSON** on the screen (not a formatted table). To view rows as a table, pipe the output to `jq` (see example below).

**NOTE** - field names must be the database field name rather than labels - use the **get forms** and **get fields** commands to verify them if in doubt.

Example:

```bash
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'"
```
Pipe results through jq:

```bash
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'" | jq .
```

Save results to a file and show a simple table:

```bash
bash hitt.sh -u "sql select [name],[Schema ID] from [AR System Metadata: arschema] where [name] like '%field%'" > /tmp/ar-query.json
jq -r '"\(.columns[0].label)\t\(.columns[1].label)", (.rows[] | [.[]] | @tsv)' /tmp/ar-query.json | column -t -s $'\t'
```

If the query fails, HITT reports an error (for example bad HTTP status, invalid JSON, or an API error message).

### `gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME`

Generates a DBID string from the values provided. **DB_TYPE** is one of `mssql`, `oracle`, or `postgres`.

### `checkpat [USERNAME] [PAT]`

Calls Docker Hub’s token service with **USERNAME** and **PAT** to verify the permissions for the **`bmchelix`** repository. On success you see a confirmation; on failure, HITT explains that the token may be limited to public-repo read-only and should be recreated with the correct access (see Docker Hub / EPD documentation).

If you omit **both** arguments, HITT looks for **bmc-dtrhub** in your Helix Platform namespace and offers those docker.io credentials. If the secret is missing or you decline, you are prompted for username and PAT.

If **USERNAME** is given but **PAT** is omitted, **PAT** is read from a hidden prompt (same pattern as other password prompts).

### `imagels IMAGE`

Lists tags for a container image repository using **skopeo** (`skopeo list-tags`). Output is JSON (pretty-printed with **jq**).

**Requirements**

1. Install **skopeo** — see [skopeo.org](https://skopeo.org/#download).
2. Log in to the registry host before running HITT:

```bash
skopeo login docker.io          # Docker Hub
skopeo login harbor.example.com # private Harbor or other registry
```

**IMAGE argument**

| Form | Resolves to |
|------|-------------|
| Short name (no `/`) | `docker.io/bmchelix/IMAGE` — for example `ars` → `docker.io/bmchelix/ars` |
| Full path (contains `/`) | Used as-is — for example `registry.example.com/project/my-image` |

Examples:

```bash
bash hitt.sh -u imagels ars
bash hitt.sh -u "imagels my-registry.example.com/bmchelix/ars"
```

If the repository is missing or you are not logged in, HITT reports an error.

### `checkrbac [hitt|deploy|all]`

Checks whether the account HITT uses has the permissions HITT and Helix deployment need. Requires Helix namespace values in your **HITT configuration** for namespace-scoped checks.

| Profile | Checks |
|--------|--------|
| **hitt** (default) | Cluster/all-namespace **read** access plus HITT-specific writes (tctl jobs, cacerts fix, Support Assistant role). Optional: metrics API, OpenShift cluster operators, pod exec. |
| **deploy** | Shared reads plus **create/update/patch/delete** permissions needed to install or upgrade Helix in your configured namespaces. Optional: HPAs. Based on [Deployment Engine RBAC](https://docs.helixops.ai/bin/Service-Management/On-Premises-Deployment/BMC-Helix-Service-Management-Deployment/brid26201/Installing/Preparing-for-installation/Setting-up-the-BMC-Deployment-Engine/) and pipeline install paths. |
| **all** | Every catalog row (hitt + deploy). |

Namespaces tested for `helix-ns` rules: Helix Platform, Helix IS, Deployment Engine, and Helix Logging (when configured in HITT; duplicates skipped).

See also: [README-fix-mode.md](README-fix-mode.md) for **`-f` fix mode** (cacerts, Jenkins, license apply, etc.).
