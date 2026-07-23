# HITT Fix Mode #

**HITT's** fix mode provides a quick way to resolve some common Helix Deployment Engine/Jenkins and post-deployment configuration issues.

## Modes ##

| Fix&nbsp;Mode   | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `ssh`    | Set up/update passwordless ssh for the git user. |
| `realm`  | Create/update the Helix Service Management realm in SSO. |
| `cacerts`  | Update the cacerts secret in the Helix IS namespace with a new file. |
| `addcert`  | Add one or more PEM certificates to the IS cacerts secret, or with `git` to `pipeline/tasks/cacerts` in the ITSM installer repository. |
| `sat`   | Create the assisttool-rl role and assisttool-rlb role-binding required by the Support Assistant Tool in the Helix IS namespace. |
| `arlicense`   | Apply an Innovation Suite/AR server license to the system via the REST API. |
| `resetssopwd`   | Resets the Helix SSO admin user password to the BMC default value. |
| `jenkins`  | Jenkins specific fixes - see below. |

### Jenkins Fixes ###
| Fix Mode       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `scriptapproval`  | Approves the scripts required by the deployment pipelines.                     |
| `pipelinelibs`  | Create/update the Global Trusted Pipeline Library definitions.              |
| `credentials`  | Create/update all the required credentials, except kubeconfig - see the 'kubeconfig' option. |
| `kubeconfig`   | Create/update the kubeconfig credential with a new kubeconfig file. |
| `all`   | Runs all of the Jenkins fixes except for 'dryrun'. |
| `dryrun`   | Trigger a dry run of all the HELIX pipelines. |
## Usage ##

Fix modes are called using the `-f <fixmode>` command line option.  Some of the fix commands require additional parameters in which case the mode and options must be enclosed in double quotes.

```bash
Examples:
bash hitt.sh -f sat # Run the Support Assistant Tool fix
bash hitt.sh -f "cacerts /tmp/newcacerts" # Update the cacerts secret with the newcacerts file
bash hitt.sh -f "addcert /path/to/custom-certs.pem" # Add PEM certificates to the IS cacerts secret
bash hitt.sh -f "addcert /path/to/custom-certs.pem git" # Add PEM certificates to pipeline/tasks/cacerts in git
```

#### `ssh` - set up passwordless ssh for the git user
```bash
bash hitt.sh -f ssh
```
Configures and tests passwordless ssh from the `git` user to the `git` user.  A new ssh key will be created if one does not already exist.\
**Note:** this option does not set up ssh from the `jenkins` user to the `git` user.  Please see the product documentation for steps to do this.

#### `realm` - set up the SSO realm for Helix Service Management
```bash
bash hitt.sh -f realm
```
Creates or updates the SSO realm required by the Helix Service management applications with values based on the IS namespace, CUSTOMER_SERVICE and ENVIRONMENT values from your **HITT configuration**.  This option may also be used to create the realm after the Helix Platform has been installed.

#### `"cacerts new-cacerts-file"` - update the cacerts secret with a new file
```bash
bash hitt.sh -f "cacerts /path/to/newcacertsfile"
```
Updates the `cacerts` secret in the Helix IS namespace with a new cacerts file.  Used when the `HELIX_ONPREM_DEPLOYMENT` pipeline was run but the cacerts file was not attached or the existing secret needs to be updated with one containing a new third party certificate.  If the new cacerts file is valid you will be prompted to confirm the update.

#### `"addcert certificates.pem"` - add PEM certificates to the IS cacerts secret

```bash
bash hitt.sh -f "addcert /path/to/custom-certs.pem"
```

Adds one or more certificates from a **PEM** file to the Java keystore in the `cacerts` secret in the Helix IS namespace. HITT downloads the current cacerts from the cluster, validates each certificate in the PEM file (expired certificates are rejected; certificates expiring within 4 weeks produce a warning), imports them into the keystore, runs the same cacerts checks used elsewhere in HITT, and asks you to confirm before replacing the secret.

Use this when pods in the IS namespace need to trust an additional CA or server certificate (for example a new third-party integration) without rebuilding the full cacerts file by hand.

#### `"addcert certificates.pem git"` - add PEM certificates to pipeline/tasks/cacerts in git

```bash
bash hitt.sh -f "addcert /path/to/custom-certs.pem git"
```

Same PEM validation and cacerts checks as above, but updates `pipeline/tasks/cacerts` in the **itsm-on-premise-installer** repository instead of the cluster secret. HITT checks out only that file (sparse checkout), imports the certificate(s), validates the keystore, then asks you to confirm before committing and pushing.

Repository location depends on your Deployment Engine setup:

- **Containerized Jenkins** — in-cluster source repository for the ITSM installer (same source used by in-cluster pipelines)
- **Standalone Jenkins** — `${GIT_REPO_DIR}/ITSM_REPO/itsm-on-premise-installer.git` from the HELIX_ONPREM_DEPLOYMENT pipeline parameters

Requires Jenkins access (to read `GIT_REPO_DIR` on standalone systems) and git push permissions to the repository.

#### `sat` - add the role and rolebinding needed by the Support Assistant Tool
```bash
bash hitt.sh -f sat
```
Creates the default role and rolebinding required by the Support Assistant Tool.  Used when SAT was deployed but the **SUPPORT_ASSISTANT_CREATE_ROLE** option was not selected.

#### `"arlicense key <expiry-date>"` - applies a server license to the system
```bash
bash hitt.sh -f "arlicense BRD-128754"
or
bash hitt.sh -f "arlicense LTD-761066 28-Apr-27"
or
bash hitt.sh -f "arlicense SHY-351098-GH-165"
```
Applies a permanent or temporary server license to the system via the AR REST API.

#### `resetssopwd` - resets the Helix SSO admin user password to the BMC default value
```bash
bash hitt.sh -f resetssopwd
```
Checks that the SSO 'Admin' user exists and prompts for confirmation before resetting the password to the default value.

### Jenkins Fixes ###
#### `"jenkins scriptapproval"` - approves Jenkins scripts
```bash
bash hitt.sh -f "jenkins scriptapproval"
```
Updates Jenkins and adds the approval required for the two scripts used by the deployment pipelines.

#### `"jenkins pipelinelibs"` - updates the Jenkins global trusted pipeline libraries
```bash
bash hitt.sh -f "jenkins pipelinelibs"
or
bash hitt.sh -f "jenkins pipelinelibs /path/to/LIBRARY_REPO"
```
Creates or updates the `pipeline-framework` and `JENKINS-27413-workaround-library` global trusted pipeline libraries.  If the path to the `LIBRARY_REPO` directory is not provided you will be prompted to select the library `.git` directory from a list.

#### `"jenkins credentials"` - updates Jenkins credentials
```bash
bash hitt.sh -f "jenkins credentials"
```
Creates or updates the Jenkins `username/password` type, `TOKEN`, and `password-vault-api` credentials used by the deployment pipelines.  You will be prompted to enter the `git` user's password.\
**Note:** does not create or update the `kubeconfig` credential - see the below.

#### `"jenkins kubeconfig"` - updates the Jenkins kubeconfig credential
```bash
bash hitt.sh -f "jenkins kubeconfig"
or
bash hitt.sh -f "jenkins kubeconfig /path/to/kubeconfig"
```
Creates or updates the Jenkins `kubeconfig` credential with the current `~/.kube/config` file or the file specified in the command.  The file is tested to make sure it is valid for the current cluster. If the new kubeconfig file is valid you will be prompted to confirm the update.

#### `"jenkins all"` - run all Jenkins fixes
```bash
bash hitt.sh -f "jenkins all"
```
Runs all of the HITT Jenkins fixes, except for 'dryrun'. Useful for configuring a new installation of Jenkins.

#### `"jenkins dryrun"` - starts a dry run of all Helix deployment pipelines
```bash
bash hitt.sh -f "jenkins dryrun"
```
Performs a dry run build of all the Helix deployment pipelines.  Used after replacing the git repository files with those for a different version during an update, or upgrade, of Helix Service Management.
