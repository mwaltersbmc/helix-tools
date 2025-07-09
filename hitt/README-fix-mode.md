# HITT Fix Mode #

**HITT**'s fix mode provides a quick way to resolve some common Helix Deployment Engine/Jenkins and post-deployment configuration issues.

## Modes ##

| Fix&nbsp;Mode   | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `ssh`    | Set up/update passwordless ssh for the git user. |
| `realm`  | Create/update the Helix Service Management realm in SSO. |
| `cacerts`  | Update the cacerts secret in the Helix IS namespace with a new file. |
| `sat`   | Create the assisttool-rl role and assisttool-rlb role-binding required by the Support Assistant Tool in the Helix IS namespace. |
| `arlicense`   | Apply an Innovation Suite/AR server license to the system. |
| `getdbid`   | Displays the database ID (DBID) for the system - used for licensing. |
| `jenkins`  | Jenkins specific fixes - see below. |

### Jenkins Fixes ###
| Fix Mode       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `scriptapproval`  | Approves the scripts required by the deployment pipelines.                     |
| `pipelinelibs`  | Create/update the Global Trusted Pipeline Library definitions.              |
| `credentials`  | Create/update all the required credentials, except kubeconfig - see the 'kubeconfig' option. |
| `kubeconfig`   | Create/update the kubeconfig credential with a new kubeconfig file. |
| `dryrun`   | Trigger a dry run of all the HELIX pipelines. |
## Usage ##

Fix modes are called using the `-f <fixmode>` command line option.  Some of the fix commands require additional parameters in which case the mode and options must be enclosed in double quotes.

```bash
Examples:
bash hitt.sh -f sat # Run the Support Assistant Tool fix
bash hitt.sh -f "cacerts ~/newcacerts" # Update the cacerts secret with the ~/newcacerts file
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
Creates or updates the SSO realm required by the Helix Service management applications with values based on the IS namespace, CUSTOMER_SERVICE and ENVIRONMENT values found in the `hitt.conf` file .  This option may also be used to create the realm after the Helix Platform has been installed.

#### `"cacerts new-cacerts-file"` - update the cacerts secret with a new file
```bash
bash hitt.sh -f "cacerts /path/to/newcacerts"
```
Updates the `cacerts` secret in the Helix IS namespace with a new cacerts file.  Used when the `HELIX_ONPREM_DEPLOYMENT` pipeline was run but the cacerts file was not attached or the existing secret needs to be updated with one containing a new third party certificate.

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
```
Applies a permanent or temporary server license to the system.

#### `getdbid` - add the role and rolebinding needed by the Support Assistant Tool
```bash
bash hitt.sh -f getdbid
```
Displays the DB ID of the system that is required to generate a server license via the BMC web site.

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
Creates or updates the Jenkins `kubeconfig` credential with the current `~/.kube/config` file or the file specified in the command.  The file is tested to make sure it is valid for the current cluster.

#### `"jenkins dryrun"` - starts a dry run of all Helix deployment pipelines
```bash
bash hitt.sh -f "jenkins dryrun"
```
Performs a dry run build of all the Helix deployment pipelines.  Used after replacing the git repository files with those for a different version during an update, or upgrade, of Helix Service Management.
