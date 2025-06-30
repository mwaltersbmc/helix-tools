# Helix IS Triage Tool (HITT)

The **Helix IS Triage Tool (HITT)** is a shell script that performs diagnostic checks for common configuration issues encountered during the installation and operation of BMC Helix IS Service Management applications.

> 💡 **Run this tool as the `git` user on the Deployment Engine system where Jenkins is installed.**

### Quick Start ###

Run the following commands as the `git` user:

```bash
mkdir hitt && cd hitt
curl -O https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh
curl -O https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz   # Optional, enables DB validation
```

## Features & Modes

HITT supports different modes for Helix and Jenkins validation:

| Mode       | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `post-hp`  | Validates Helix Platform and RSSO realm configuration.                     |
| `jenkins`  | Verifies Jenkins setup (nodes, credentials, libraries, etc.).              |
| `pre-is`   | Run after `HELIX_GENERATE_CONFIG` pipeline completes. Validates pipeline inputs. |
| `post-is`  | Performs post-deployment checks of Helix Service Management.               |

> Each mode targets a different stage of the deployment lifecycle.

The HITT script requires minimal manual configuration and will read the information it needs from Kubernetes, Jenkins, and the CUSTOMER_CONFIGS git repository.

There are some optional tests that will attempt to validate the Helix IS database.  These require the use of a Java SQL client, called JISQL, and JDBC drivers for each database type.  To enable these tests, download the dbjars.tgz file and save it in the same directory as the hitt.sh script.  HITT will run the SQL checks when this file is present.

### Configuration ###

HITT is configured by a file called `hitt.conf` which, if not found, is created when the script is run. You will be prompted to select your Helix namespaces and enter the other required settings.  If you need to change any of the values, either edit the file or delete it so that it is recreated the next time HITT is used. There is also a section where you can enter details about your Jenkins which may be left as-is unless it requires credentials, uses https, or is running on a non-default port. Enclose the `JENKINS_USERNAME` and `JENKINS_PASSWORD` values in single quotes.  If your Jenkins is configured to use SSL change the `JENKINS_PROTOCOL` to `https` and set the `JENKINS_PORT` appropriately.

The hitt.conf file:

```
# REQUIRED SETTINGS
# Enter your Helix namespace names and HELIX_ONPREM_DEPLOYMENT pipeline values for CUSTOMER_SERVICE and ENVIRONMENT
HP_NAMESPACE=
IS_NAMESPACE=
IS_CUSTOMER_SERVICE=
IS_ENVIRONMENT=

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
chmod a+x hitt.sh
./hitt.sh
```

HITT requires one command line option (-m) to specify the operating mode, unless being used for tctl commands, and will print a usage message if this is not provided.

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

HITT creates various log files in the directory that the script is run from:

- `hitt.log` - script output.
- `hittmsgs.log` - additional details on the cause, impact, and steps to fix, warnings and errors reported by the script.
- `values.*` - the pipeline input values in pre-is mode, or values read from the cluster for post-is.
- `PIPELINE_NAME.log` - console output for each of the Jenkins pipelines.
- `k8s*.log` - output from various kubectl commands such as 'get pods'.
- `hittdebug.log` - error messages from commands run by the script which may be useful if it does not work as expected.
- `*.txt` - text only versions of log files with formatting and colour codes removed.

All of the files are added to `hittlogs.zip` which can be sent to BMC Support if needed.

There are some additional messages which are not logged by default but can be enabled with the `-v` switch.\
Quiet mode `-q` only prints the summary messages.

**NOTE** - passwords are not logged unless the `-p` switch is used.

### tctl Mode ###

HITT may also be used to run simple `tctl` commands such as `get tenant` and `get service`.  This deploys the same job and pod used by the Jenkins HELIX_ITSM_INTEROPS pipeline and avoids having to download and configure the tctl client on a local system.  Use the `-t` switch along with the command to run enclosed in quotes:

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

### Advanced CLI Options ###

There are several extra command line switches which may be helpful for troubleshooting.

`-c`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Do not delete temporary files after execution.\
`-d`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enables `set -x` debugging output.\
`-e #`&nbsp;&nbsp;&nbsp;&nbsp;Exit script on the specified error number `#`.  Use `-e 0` to stop on the first error.\
`-j`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Display the Jenkins credentials details and save kubeconfig contents as kubeconfig.jenkins.\
`-p`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Output pipeline passwords in the `values.log` file when running in pre-is mode.\
`-q`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Quiet mode - only print summary.\
`-v`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Increase verbosity of logging.\
`-x`&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ignore proxy environment variables.

### Checks Summary ###

HITT performs over 150 diagnostic checks based on the selected mode, including:

- Required CLI tools and version validation
- A valid kubeconfig file is present or configured via the KUBECONFIG environment variable.
- Kubernetes namespace health and pod status
- Platform and IS component version discovery
- Helix Platform and RSSO realm configuration
- Jenkins libraries, credentials, and pipeline config
- FTS and IS server validation
- Database access and tenant checks (if `dbjars.tgz` is available)
