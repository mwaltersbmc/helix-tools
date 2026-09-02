# HITT Fix Mode

**Fix mode** (`-f`) helps resolve common Deployment Engine (Jenkins) and post-deployment configuration issues.

When a fix command has more than one word, enclose the whole value in **double quotes**:

```bash
bash hitt.sh -f sat
bash hitt.sh -f "cacerts /tmp/newcacerts"
bash hitt.sh -f "addcert /path/to/custom-certs.pem"
bash hitt.sh -f "addcert /path/to/custom-certs.pem git"
```

## Fix commands

| Fix | Description |
|-----|-------------|
| `ssh` | Set up or update passwordless SSH for the `git` user. |
| `realm` | Create or update the Helix Service Management SSO realm. |
| `cacerts` | Update the **cacerts** secret in the Helix IS namespace with a new file. |
| `addcert` | Add one or more PEM certificates to the IS **cacerts** secret, or with `git` to **pipeline/tasks/cacerts** in the ITSM installer repository. |
| `sat` | Create the role and role-binding required by the Support Assistant Tool in the Helix IS namespace. |
| `arlicense` | Apply an Innovation Suite / AR server license via the REST API. |
| `resetssopwd` | Reset the Helix SSO admin user password to the BMC default value. |
| `jenkins` | Deployment Engine fixes — see [Jenkins fixes](#jenkins-fixes). |

### Jenkins fixes

| Fix | Description |
|-----|-------------|
| `scriptapproval` | Approve the scripts required by the deployment pipelines. |
| `pipelinelibs` | Create or update global trusted pipeline library definitions. |
| `credentials` | Create or update required credentials (except kubeconfig — use `kubeconfig`). |
| `kubeconfig` | Create or update the kubeconfig credential from a kubeconfig file. |
| `all` | Run all Jenkins fixes except `dryrun`. |
| `dryrun` | Trigger a dry run of all HELIX pipelines. |

Invoke Jenkins fixes as `bash hitt.sh -f "jenkins <fix>"` (for example `bash hitt.sh -f "jenkins all"`).

## `ssh`

```bash
bash hitt.sh -f ssh
```

Configures and tests passwordless SSH from the `git` user to the `git` user. A new SSH key is created if one does not already exist.

**Note:** This does not set up SSH from the `jenkins` user to the `git` user. See the product documentation for that step.

## `realm`

```bash
bash hitt.sh -f realm
```

Creates or updates the SSO realm required by Helix Service Management applications, using your configured **CUSTOMER_SERVICE**, **ENVIRONMENT**, and Helix IS namespace. May also be used after Helix Platform is installed.

## `"cacerts new-cacerts-file"`

```bash
bash hitt.sh -f "cacerts /path/to/newcacertsfile"
```

Updates the **cacerts** secret in the Helix IS namespace with a new Java keystore file. Use when **HELIX_ONPREM_DEPLOYMENT** ran without the cacerts attachment, or when the secret must include a new third-party certificate. If the file is valid, HITT prompts you to confirm before updating the secret.

## `"addcert certificates.pem"`

```bash
bash hitt.sh -f "addcert /path/to/custom-certs.pem"
```

Adds one or more certificates from a **PEM** file to the Java keystore in the **cacerts** secret in the Helix IS namespace. HITT downloads the current keystore from the cluster, validates each certificate (expired certificates are rejected; certificates expiring within four weeks produce a warning), imports them, runs the same cacerts checks used elsewhere in HITT, and asks you to confirm before replacing the secret.

Use this when Helix IS pods need to trust an additional CA or server certificate without rebuilding the full keystore by hand.

## `"addcert certificates.pem git"`

```bash
bash hitt.sh -f "addcert /path/to/custom-certs.pem git"
```

Same PEM validation and keystore checks as above, but updates **pipeline/tasks/cacerts** in the **itsm-on-premise-installer** repository instead of the cluster secret. HITT updates only that file in git, imports the certificate(s), validates the keystore, then asks you to confirm before committing and pushing.

Repository location depends on your Deployment Engine setup:

- **Containerized Deployment Engine** — in-cluster source repository for the ITSM installer (same source used by in-cluster pipelines)
- **Standalone Deployment Engine** — ITSM installer repository path from the **GIT_REPO_DIR** value on **HELIX_ONPREM_DEPLOYMENT**

You need permission to push to that repository. On a standalone Deployment Engine, HITT reads **GIT_REPO_DIR** from the pipeline job to locate the repo.

## `sat`

```bash
bash hitt.sh -f sat
```

Creates the role and role-binding required by the Support Assistant Tool. Use when Support Assistant was deployed but **SUPPORT_ASSISTANT_CREATE_ROLE** was not selected.

## `"arlicense key [expiry-date]"`

```bash
bash hitt.sh -f "arlicense BRD-128754"
bash hitt.sh -f "arlicense LTD-761066 28-Apr-27"
bash hitt.sh -f "arlicense SHY-351098-GH-165"
```

Applies a permanent or temporary server license via the AR REST API.

## `resetssopwd`

```bash
bash hitt.sh -f resetssopwd
```

Checks that the SSO **Admin** user exists and prompts for confirmation before resetting the password to the BMC default value.

## Jenkins fixes

### `"jenkins scriptapproval"`

```bash
bash hitt.sh -f "jenkins scriptapproval"
```

Approves the scripts used by the deployment pipelines.

### `"jenkins pipelinelibs"`

```bash
bash hitt.sh -f "jenkins pipelinelibs"
bash hitt.sh -f "jenkins pipelinelibs /path/to/LIBRARY_REPO"
```

Creates or updates the **pipeline-framework** and **JENKINS-27413-workaround-library** global trusted pipeline libraries. If you do not pass a path to the library repository, HITT prompts you to select the library `.git` directory from a list.

### `"jenkins credentials"`

```bash
bash hitt.sh -f "jenkins credentials"
```

Creates or updates the Jenkins credentials used by the deployment pipelines. You are prompted for the `git` user password.

**Note:** Does not create or update the **kubeconfig** credential — use `jenkins kubeconfig`.

### `"jenkins kubeconfig"`

```bash
bash hitt.sh -f "jenkins kubeconfig"
bash hitt.sh -f "jenkins kubeconfig /path/to/kubeconfig"
```

Creates or updates the Jenkins **kubeconfig** credential from `~/.kube/config` or the file you specify. HITT validates the file for the current cluster and prompts you to confirm before updating the credential.

### `"jenkins all"`

```bash
bash hitt.sh -f "jenkins all"
```

Runs all HITT Jenkins fixes except `dryrun`. Useful when configuring a new Deployment Engine installation.

### `"jenkins dryrun"`

```bash
bash hitt.sh -f "jenkins dryrun"
```

Starts a dry run of all Helix deployment pipelines. Use after replacing git repository files for a different version during an update or upgrade of Helix Service Management.

## See also

- [Main HITT guide](README.md)
- [Utility mode](README-utility-mode.md) — `-u` helpers
- [Pipeline mode](README-pipeline-mode.md) — `-k` get / build / kickstart
- Step-by-step use cases: https://bit.ly/hitthelp
