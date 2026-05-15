# HITT Utility Mode

**HITT** utility mode provides small helpers for Helix deployments (DBID/JWT, secret decode, generated DBID).

Utility commands are invoked with **`-u`**. When the command has spaces or multiple words, pass the whole thing in **double quotes**.

## Commands

| Command | Description |
|--------|-------------|
| `get dbid` | Displays the database ID (DBID) for the system (used for licensing). |
| `get jwt` | Prints an AR-JWT for the IS REST API. Defaults to `hannah_admin` using credentials from the cluster; optional username/password. |
| `get secret` | Decodes and displays Kubernetes secret `.data`. Binary keys are written to files; remaining keys are printed. Args: **SECRETNAME** **NAMESPACE**. |
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

### `gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME`

Generates a DBID string from the values provided. **DB_TYPE** is one of `mssql`, `oracle`, or `postgres`.

See also: [README-fix-mode.md](README-fix-mode.md) for **`-f` fix mode** (cacerts, Jenkins, license apply, etc.).
