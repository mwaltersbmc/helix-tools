# Helix IS Triage Tool (HITT)
**Latest build `20260723-01`**

The **Helix IS Triage Tool (HITT)** is a shell script that performs diagnostic checks for common configuration issues encountered during the installation and operation of BMC Helix IS Service Management applications.

> 💡 **Run this tool as the `git` user on the Deployment Engine system where Jenkins is installed.**

#### **Interactive help page with HITT use-cases available at https://bit.ly/hitthelp**


### Quick Start ###

Run the following commands as the `git` user:

```bash
mkdir hitt && cd hitt && curl -skO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh && chmod a+x hitt.sh
curl -skO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz   # Optional, enables DB validation
```

- [Features & Modes](#features--modes)
- [Configuration](#configuration)
- [Proxy Support](#proxy-support)
- [Running HITT](#running-hitt)
- [Log Files](#log-files)
- [Pipeline Mode](README-pipeline-mode.md)
- [tctl Mode](#tctl-mode)
- [Bundle Deployment Status](#get-is-bundle-deployment-status)
- [Advanced CLI Options](#advanced-cli-options)
- [Help](#help)
- [Config overrides](#config-overrides)
- [Build version (developers)](#build-version-developers-git-clone-only)
- [Fix mode](README-fix-mode.md) (`-f`) — targeted fixes (cacerts, addcert, Jenkins, license, …)
- [Utility mode](README-utility-mode.md) (`-u`) — helpers (`get secret`, `get jwt`, `get dbid`, `get arlicense`, `gendbid`, `imagels`, `checkpat`)
- [Pipeline mode](README-pipeline-mode.md) (`-k`) — `get` / `build` / `kickstart` / `delete` for **HELIX_ONPREM_DEPLOYMENT**
- [Info mode](README-info-mode.md) (`-m info`) — environment summaries (**under development**): `info cluster`, `info helix`, `info ingress`, `info full`

Built-in summaries: `bash hitt.sh -h` (general help), `bash hitt.sh -h fix`, `bash hitt.sh -h utility`, `bash hitt.sh -h pipeline`, `bash hitt.sh -h consolelog`, `bash hitt.sh -h info`, and `bash hitt.sh -h override`. You can also run `bash hitt.sh -f help`, `bash hitt.sh -u help`, `bash hitt.sh -k help`, `bash hitt.sh -o help`, or `bash hitt.sh -m "info help"` from within each mode.

**Info ingress** (`bash hitt.sh -m "info ingress"`) — read-only ingress controller summary for the Helix **`INGRESS_CLASS`**: workload type, namespace, workload name, and controller image. Requires **HITT configuration** with the Helix Platform namespace set. See [README-info-mode.md](README-info-mode.md#ingress--ingress-controller-summary).

**Quoting:** HITT options whose values contain spaces must be double-quoted (e.g. `-m "info ingress"`, `-f "jenkins kubeconfig"`, `-u "get jwt"`). See [README-info-mode.md](README-info-mode.md) for info mode examples.

### Build version (developers, git clone only)

`hitt.sh` defines **`HITT_BUILD_VERSION`** (`YYYYMMDD-NN` in **UTC**, `NN` zero-padded **01–99**). It is shown in the welcome line when you run the script, and the second line of this README (bold **Latest build** with the version in backticks) is updated to match when the pre-commit hook runs for a commit that stages **`hitt/hitt.sh`**.

If you work from a **git clone** of this repo, enable the hook so the counter advances when **`hitt/hitt.sh`** is included in a commit:

```bash
git config core.hooksPath .githooks
```

To make one commit without bumping: `SKIP_HITT_VERSION_HOOK=1 git commit ...`

`curl` installs of `hitt.sh` alone keep the version baked into the file at publish time (no hook).

## Features & Modes

HITT supports different modes for Helix and Jenkins validation:

| Mode       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `post-hp`  | Validates Helix Platform and RSSO realm configuration.                     |
| `jenkins`  | Verifies Jenkins setup (nodes, credentials, libraries, etc.).              |
| `pre-is`   | Run after `HELIX_GENERATE_CONFIG` pipeline completes. Validates pipeline inputs. |
| `post-is`  | Performs post-deployment checks of Helix Service Management.               |

> Each mode targets a different stage of the deployment lifecycle.

The HITT script requires minimal configuration and will read the information it needs from Kubernetes, Jenkins, and the CUSTOMER_CONFIGS git repository.

There are some optional tests that will attempt to validate the Helix IS database.  These require the use of a Java SQL client, called JISQL, and JDBC drivers for each database type.  To enable these tests, download the dbjars.tgz file and save it in your HITT directory.  HITT will run the SQL checks when this file is present.

### Configuration ###

HITT is configured by a file called `hitt.conf` which, if not found, is created when the script is run. You will be prompted to select your Helix namespaces and enter the other required settings.

When the config file is created interactively, HITT scans the cluster for namespaces that look like Helix Platform, Helix IS, and (when the Deployment Engine runs in the cluster) the containerized Deployment Engine. If exactly one namespace matches a role, HITT asks **y/n** to confirm that namespace; answer **n** to open a menu of discovered candidates plus **Other** (full cluster namespace list). If several namespaces match a role, the menu lists those candidates and **Other**. If none match, you choose from all cluster namespaces. For Helix IS, when the sole candidate is the same as the Platform namespace already chosen, HITT skips the confirmation and shows the candidate menu with **Other**.

If you need to change any of the values, either edit the file or delete it so that it is recreated the next time HITT is used.

You can use a different config file by using the `-c filename` command line option.  This may be useful when using the pipeline mode option to migrate pipeline values between Jenkins systems.

You can override individual settings from **hitt.conf** on the command line without editing the file — for example when testing against a different namespace or Jenkins login. See [Config overrides](#config-overrides) or run `bash hitt.sh -h override`.

The `hitt.conf` file:

```
# REQUIRED SETTINGS
# Enter your Helix namespace names and HELIX_ONPREM_DEPLOYMENT pipeline values for CUSTOMER_SERVICE and ENVIRONMENT
HP_NAMESPACE=
IS_NAMESPACE=
IS_CUSTOMER_SERVICE=
IS_ENVIRONMENT=
CDE_NAMESPACE=

# OPTIONAL SETTINGS
# Set JENKINS credentials and hostname/port if required
JENKINS_USERNAME=''
JENKINS_PASSWORD=''
JENKINS_HOSTNAME=localhost
JENKINS_PROTOCOL=http
JENKINS_PORT=8080
```

Finally, there is a section for the command line tools that the script uses.  It is assumed that these are installed and available in directories that are included in the PATH environment variable of the user running the script.  HITT will check that these tools are present and report any that can't be found.  Missing tools must be installed, or the full path to their location set, if they are not in the PATH.

### Proxy Support ###

HITT supports connection to https services via a proxy.  If your system has an `https_proxy` environment variable set the script will use the value for curl, openssl and SSLPoke commands.  Proxy authentication and `no_proxy` settings are also picked up.

### Running HITT ###

Run the script using bash or make it executable with chmod if preferred.

```bash
bash hitt.sh
OR
./hitt.sh
```

HITT requires one command line option (`-m`) to specify the operating mode, unless being used for tctl commands, and will print a usage message if this is not provided. Run `bash hitt.sh -h` for general help and a list of mode-specific help topics.

```bash
bash hitt.sh
Helix IS Triage Tool (HITT)
Usage: bash hitt.sh -m <post-hp|pre-is|post-is|jenkins>

Examples:
bash hitt.sh -m post-hp  - run post HP installation only checks
OR
bash hitt.sh -m pre-is   - run IS pre-installation checks
OR
bash hitt.sh -m post-is  - run IS post-installation checks
OR
bash hitt.sh -m jenkins  - run Jenkins configuration checks

Use post-hp after successfully installing the Helix Platform but before using Jenkins.
Use pre-is after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS.
Use post-is for troubleshooting after IS deployment.
Use jenkins to validate Jenkins config - nodes, credentials, libraries etc.
```

HITT will print the results of the checks and tests as they are run.  Errors and warnings are noted with highlighted messages and summarised at the end.  A `hittmgs.log` file is created which contains more detailed information, including the impact and suggested fix, for each error/warning.

<span style="color:red">ERRORS</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- indicate problems which are likely to cause installation failures, or result in problems post-install.\
<span style="color:yellow">WARNINGS</span>&nbsp;&nbsp;&nbsp;- highlight potential problems or settings which may be appropriate under some conditions, but are usually recommended to be different.

When the test being run produces additional output, pod status for example, this is displayed after the related ERROR or WARNING.

All of the tests are read-only and will not make changes to the system.  However, please note that the checks which discover the tenant and service details from the Helix Platform deploy a tctl job/pod in the same way as the Jenkins HELIX_ITSM_INTEROPS pipeline.  The job/pod are deleted after use.

### Logging ###

HITT creates various log files in your HITT directory:

- `hitt.log` - script output.
- `hittmsgs.log` - additional details on the cause, impact, and steps to fix, warnings and errors reported by the script.
- `values.*` - the pipeline input values in pre-is mode, or values read from the cluster for post-is.
- `PIPELINE_NAME.log` - console output for each of the Jenkins pipelines.
- `k8s*.log` - output from cluster status checks (for example pod listings).
- `hittdebug.log` - error messages from commands run by the script which may be useful if it does not work as expected.
- `*.txt` - text only versions of log files with formatting and colour codes removed.

All of the files are added to `hittlogs.zip` which can be sent to BMC Support if needed.

There are some additional messages which are not logged by default but can be enabled with the `-v` switch.\
Quiet mode `-q` only prints the summary messages.

**NOTE** - pipeline passwords are redacted in `-k get` output unless `-p` is used; in pre-is mode, passwords are omitted from `values.log` unless `-p` is used.

### Pipeline Mode ###

Pipeline mode (`-k`) exports and submits **`HELIX_ONPREM_DEPLOYMENT`** parameters on the Deployment Engine configured in your **HITT settings**: **`get`** (export JSON, including **`get kickstart`** from Platform discovery), **`build`** (queue from file), **`kickstart`** (prefill and queue in one step), and **`delete`** (remove builds from job history).

See **[README-pipeline-mode.md](README-pipeline-mode.md)** for requirements, quoting, the rebuild-in-Jenkins workflow, and what the build trigger applies automatically.

Password parameters in **get** output are redacted unless **`-p`** is used (see [get — save parameter values](README-pipeline-mode.md#get--save-parameter-values)).

```bash
bash hitt.sh -k "get lastsuccessful values.json"
bash hitt.sh -p -k "get lastsuccessful values.json"   # include plain passwords for build/migration
bash hitt.sh -p -k "get kickstart deploy-params.json"   # save known values; edit, then build
bash hitt.sh -k "build deploy-params.json"
bash hitt.sh -k kickstart
```

Use **`-o`** to print Deployment Engine logs on screen: **`-o jenkins`** (system log), **`-o agent`** (jenkins-agent node log), or **`-o PIPELINE_NAME`** for the latest console log from a job (documented in [README-pipeline-mode.md](README-pipeline-mode.md#view-logs-from-the-deployment-engine--o)).

### tctl Mode ###

HITT may also be used to:
 - generate a `tctl` config file.

 Output is displayed on the screen or may be redirected to a file for use by `tctl`.

 ```bash
 bash hitt.sh -t config
 # Examples:
 bash hitt.sh -t config
 bash hitt.sh -t config > config
 ```

 - run simple `tctl` commands such as `get tenant` and `get service`.

 Running commands deploys the same job and pod used by the Jenkins HELIX_ITSM_INTEROPS pipeline which avoids having to download and configure the tctl client on a local system.  Use the `-t` switch along with the command to run enclosed in quotes:

```bash
bash hitt.sh -t "tctl command"
# Examples:
bash hitt.sh -t "get tenant"
bash hitt.sh -t "get tenant 1912102789 -o json"
```

Output will be displayed on the console when the job completes.

### Get IS Bundle Deployment Status ###

You can get the deployment status of IS bundles using the ID displayed in the pipeline console output.  For example, where you something like this, use the ID at the end of the URL.

```
You may use the below status URI to check deployment status under a valid logged in session.
STATUS URI: http://platform-admin-ext:8008/api/rx/application/bundle/deploymentstatus/IDGIUNLUI5ENUASTJV8FSTJV8FT3JQ
```

Run HITT with the `-b BUNDLE-ID` option to display the status of the bundle:

```bash
$ bash hitt.sh -b IDGIUNLUI5ENUASTJV8FSTJV8FT3JQ

Running IS deployment status check for bundle ID IDGIUNLUI5ENUASTJV8FSTJV8FT3JQ...
{
  "packageDeployStatus": "DeployedWithImportWarning",
  "packageId": "IDGIUNLUI5ENUASTJV8FSTJV8FT3JQ",
  "packageName": "com.bmc.dsm.shared-services-lib",
  "packageVersion": "25.1.00-SNAPSHOT",
  "serverDeploymentStatus": {
    "platform-fts-0.platform-fts": "Deployed"
  },
  "currentServersInSync": true,
  "newlyAddedServers": [],
  "deploymentParsedStatus": {
    "importingServer": "platform-fts-0.platform-fts:10.42.4.75",
    "definitionsOverallImportStatus": "IMPORT_DEFINITIONS_SUCCESS",
    "dataOverallImportStatus": "IMPORT_DATA_WARNING",
    "errorMessages": [],
    "definitionsStatusContent": [],
    "tenantDataStatusContent": {
      "0": [
        "WARNING (303): Form does not exist on server; IDGAA5V0GFCOUAOMED7QOLIHTYQ6J0",
        "WARNING (303): Form does not exist on server; IDGAA5V0GFCOUAOMED7QOLIHTYQ6J0"
      ]
    }
  }
}
```

### Display Jenkins logs ###

Use **`-o`** to print logs from the Deployment Engine on screen. Requires **HITT configuration** and a working login to the Deployment Engine.

| Command | What you get |
|---------|----------------|
| `bash hitt.sh -o jenkins` | Recent Jenkins **system** log (controller messages). |
| `bash hitt.sh -o agent` | **jenkins-agent** node log (pipeline worker). |
| `bash hitt.sh -o helix_onprem_deployment` | Console output from the **latest build** of that job. |

**Pipeline console example** — job name as shown in the Jenkins URL (underscores, usually lowercase):

```bash
$ bash hitt.sh -o helix_onprem_deployment

Welcome to the Helix IS Triage Tool - Tue Jul 29 04:00:35 AM CDT 2025.

Checking KUBECONFIG file...

        Jenkins version 2.504.2 found on http://localhost:8080

Started by user jenkins
Checking out git ssh://git@bcx-aus-ae931ed.bmc.com/home/git/git_repos/ITSM_REPO/itsm-on-premise-installer.git into /var/lib/jenkins/workspace/HELIX_ONPREM_DEPLOYMENT@script/f800e028f92c79b5b7545feb0b85328f01f45790e00dfe4a3ef1e757ca639e59 to read pipeline/jenkinsfile/HELIX_ONPREM_DEPLOYMENT.jenkinsfile
The recommended git tool is: NONE
No credentials specified
 > git rev-parse --resolve-git-dir /var/lib/jenkins/workspace/HELIX_ONPREM_DEPLOYMENT@script/f800e028f92c79b5b7545feb0b85328f01f45790e00dfe4a3ef1e757ca639e59/.git # timeout=10
Fetching changes from the remote Git repository
 > git config remote.origin.url ssh://git@bcx-aus-ae931ed.bmc.com/home/git/git_repos/ITSM_REPO/itsm-on-premise-installer.git # timeout=10
Fetching upstream changes from ssh://git@bcx-aus-ae931ed.bmc.com/home/git/git_repos/ITSM_REPO/itsm-on-premise-installer.git
 > git --version # timeout=10
 > git --version # 'git version 2.47.1'
 > git fetch --tags --force --progress -- ssh://git@bcx-aus-ae931ed.bmc.com/home/git/git_repos/ITSM_REPO/itsm-on-premise-installer.git +refs/heads/*:refs/remotes/origin/* # timeout=10
 > git rev-parse refs/remotes/origin/master^{commit} # timeout=10
Checking out Revision cc2013d91e7f786c9a744527dfc61a29c00e7338 (refs/remotes/origin/master)
 > git config core.sparsecheckout # timeout=10
 > git checkout -f cc2013d91e7f786c9a744527dfc61a29c00e7338 # timeout=10
```

### Advanced CLI Options ###

There are several extra command line switches which may be helpful for troubleshooting.

`-c filename`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Use alternative config file.\
`-d`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enables `set -x` debugging output.\
`-e #`&nbsp;&nbsp;&nbsp;During a mode run, exit when message `#` is raised. Use `-e 0` to stop on the first error or warning. With no mode (e.g. `bash hitt.sh -e 127`), print long help for message `#` and exit.\
`-j`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Display the Jenkins credentials details and save kubeconfig contents as kubeconfig.jenkins.\
`-p`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Include plain pipeline password values in `-k get` output and in `values.log` during pre-is mode.
`-q`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Quiet mode - only print summary.\
`-v`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Increase verbosity of logging.\
`-x`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ignore proxy environment variables.\
`-z`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Do not delete temporary files after execution.

See also [Help](#help) and [Config overrides](#config-overrides).

### Help ###

Run `bash hitt.sh -h` for general usage and a list of topics. Each topic prints the same summary you get from the mode’s built-in `help` command:

| Command | Shows |
|---------|--------|
| `bash hitt.sh -h` | General usage and links to topic help |
| `bash hitt.sh -h fix` | Fix mode options ([README-fix-mode.md](README-fix-mode.md)) |
| `bash hitt.sh -h utility` | Utility mode options ([README-utility-mode.md](README-utility-mode.md)) |
| `bash hitt.sh -h pipeline` | Pipeline mode options ([README-pipeline-mode.md](README-pipeline-mode.md)) |
| `bash hitt.sh -h consolelog` | Deployment Engine log options (`-o`; [README-pipeline-mode.md](README-pipeline-mode.md#view-logs-from-the-deployment-engine--o)) |
| `bash hitt.sh -h info` | Info mode options ([README-info-mode.md](README-info-mode.md)) |
| `bash hitt.sh -h override` | Config override switches (see below) |

### Config overrides ###

These uppercase switches replace the matching value from **hitt.conf** for a single run. Combine them with any mode (for example `-m pre-is`):

| Switch | Setting in hitt.conf |
|--------|----------------------|
| `-C VALUE` | `IS_CUSTOMER_SERVICE` |
| `-D VALUE` | `CDE_NAMESPACE` (Jenkins namespace when Jenkins runs in the cluster) |
| `-E VALUE` | `IS_ENVIRONMENT` |
| `-H VALUE` | `HP_NAMESPACE` |
| `-I VALUE` | `IS_NAMESPACE` |
| `-J VALUE` | Full Jenkins URL (overrides hostname, port, and protocol) |
| `-P VALUE` | `JENKINS_PASSWORD` |
| `-U VALUE` | `JENKINS_USERNAME` |

Example — run pre-is checks against specific namespaces and pipeline values without editing the config file:

```bash
bash hitt.sh -m pre-is -H my-hp-ns -I my-is-ns -C myservice -E prod
```

Run `bash hitt.sh -h override` for the same list on the console.

### Checks Summary ###

HITT performs over 150 diagnostic checks based on the selected mode, including:

- Required CLI tools and version validation
- Kubernetes namespace health and pod status
- Platform and IS component version discovery
- Helix Platform and RSSO realm configuration
- Jenkins libraries, credentials, and pipeline config
- FTS and IS server validation
- Database access and tenant checks (if `dbjars.tgz` is available)
