# HITT Utility Mode

**HITT** utility mode provides small helpers for Helix deployments (DBID/JWT, secret decode, ConfigMap export, generated DBID).

Utility commands are invoked with **`-u`**. When the command has spaces or multiple words, pass the whole thing in **double quotes**.

## Commands

| Command | Description |
|--------|-------------|
| `get dbid` | Displays the database ID (DBID) for the system (used for licensing). |
| `get jwt` | Prints an AR-JWT for the IS REST API. Defaults to `hannah_admin` using credentials from the cluster; optional username/password. |
| `get secret` | Decodes and displays Kubernetes secret `.data`. Binary keys are written to files; remaining keys are printed. Args: **SECRETNAME** **NAMESPACE**. |
| `get configmap` | Exports ConfigMap `.data` and `.binaryData` keys to files under a new directory (named after the ConfigMap, with a numeric suffix if that name already exists). Args: **CM_NAME** **NAMESPACE**. |
| `gendbid` | Generates a database ID (DBID) from **DB_TYPE**, **DATABASE_HOST_NAME**, and **AR_DB_NAME**. |
| `help` | Prints the same summary as this file (built into the script). |

## Usage

```bash
# Current DBID from the running system
bash hitt.sh -u "get dbid"

# JWT for hannah_admin (cluster credentials)
bash hitt.sh -u "get jwt"

# JWT for another user (password prompted if not given)
bash hitt.sh -u "get jwt myuser"

# Decode a secret (secret name, then namespace)
bash hitt.sh -u "get secret ar-global-secret helix-is"

# Export a ConfigMap (name, then namespace) — creates a directory in the current working directory
bash hitt.sh -u "get configmap my-configmap helix-is"

# Generate DBID before deployment / license (mssql | oracle | postgres)
bash hitt.sh -u "gendbid mssql my-db-server.acme.com arsystem"

bash hitt.sh -u help
```

### `get dbid`

Uses `hitt.conf`, cluster access, and IS REST to print the current DBID.

### `get jwt`

- With no username: uses **hannah_admin** and resolves password from the cluster (same path as normal HITT checks).
- With a username: uses that user; password is taken from the second argument if present, otherwise prompted.

### `get secret SECRETNAME NAMESPACE`

Runs `kubectl get secret SECRETNAME -n NAMESPACE -o json`, base64-decodes `.data` entries, and:

- Prints `key: value` lines for values that look printable (ASCII-safe).
- For other keys, writes decoded bytes to uniquely named files in the current directory and prints a short log line.

### `get configmap CM_NAME NAMESPACE`

Runs `kubectl get configmap CM_NAME -n NAMESPACE -o json`. If the ConfigMap is missing, the command fails with an error.

Otherwise it creates a directory under the current working directory named **CM_NAME** (or **CM_NAME.1**, **CM_NAME.2**, … if that name already exists). Each key in `.data` is written as a UTF-8 text file named after the key; each key in `.binaryData` is base64-decoded and written as raw bytes to a file named after the key. Keys containing `/` or `..` are rejected. A short summary line is printed with counts and the directory path.

### `gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME`

Generates a DBID string from the values provided. **DB_TYPE** is one of `mssql`, `oracle`, or `postgres`.

See also: [README-fix-mode.md](README-fix-mode.md) for **`-f` fix mode** (cacerts, Jenkins, license apply, etc.).
