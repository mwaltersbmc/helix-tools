**BMC internal download command**
```shell
wget http://goto.bmc.com/gethitt -O hitt.sh
```

**External customer download command**
```shell
wget https://github.com/mwaltersbmc/helix-tools/raw/main/hitt/hitt.sh
```



The Helix IS Triage Tool (HITT) is a shell script designed to check for common configuration issues that might cause problems during the installation and use of Helix IS Service Management applications. This script is intended to be run on the system where the Helix Platform deployment manager was executed and where Jenkins is installed.

### HITT Operating Modes
HITT has three modes of operation, which all require the Helix Platform to be installed first:

1. **post-hp**: Used after installing the Helix Platform and creating the SSO realm for Helix IS.
2. **pre-is**: Used after successfully building the Jenkins HELIX_ONPREM_DEPLOYMENT pipeline with all parameters set and the HELIX_GENERATE_CONFIG option selected.
3. **post-is**: Used after completing the installation of Helix IS.

In all modes, HITT requires minimal configuration and automatically reads additional information from Kubernetes, Jenkins, and the CUSTOMER_CONFIGS git repository.

### Optional Database Validation Tests
HITT can perform optional tests to validate the Helix IS database using a Java SQL client called JISQL and JDBC drivers for each database type. To enable these tests, download the `dbjars.tgz` file and place it in the directory with the `hitt.sh` script. HITT will detect, unpack, and use these files for the SQL checks.

### Configuration
HITT is configured via a file named `hitt.conf`, which is created the first time the script is run. You will be prompted to select your namespaces and enter the other required variables.  

```shell
# REQUIRED SETTINGS
HP_NAMESPACE=
IS_NAMESPACE=
IS_CUSTOMER_SERVICE=
IS_ENVIRONMENT=

# OPTIONAL SETTINGS
JENKINS_USERNAME=
JENKINS_PASSWORD=
JENKINS_HOSTNAME=localhost
JENKINS_PORT=8080
```

The script assumes that all necessary command line tools are installed and available in the user's PATH. HITT will check for these tools and report any that are missing. If a tool is not in the PATH, you can specify its full path in the configuration file.

### Running HITT
To run the script, you can use bash or make it executable with `chmod`:

```shell
$ bash hitt.sh
OR
$ chmod a+x hitt.sh
$ ./hitt.sh
```

HITT requires a mode to be specified using the `-m` option and will display a usage message if this option is not provided:

```shell
$ bash hitt.sh
Helix IS Triage Tool (HITT)
Usage: bash hitt.sh -m <post-hp|pre-is|post-is> [-f HITT_CONFIG_FILE]

Examples:
bash hitt.sh -m post-hp  # Run post HP installation only checks
bash hitt.sh -m pre-is   # Run IS pre-installation checks
bash hitt.sh -m post-is  # Run IS post-installation checks
```

- Use **post-hp** after installing the Helix Platform but before using Jenkins.
- Use **pre-is** after running the HELIX_GENERATE_CONFIG pipeline but before deploying Helix IS.
- Use **post-is** for troubleshooting after IS deployment.
- Optionally, use `-f` to specify a different configuration file.

### Output and Error Handling
HITT will display a running summary of the checks it performs. Errors and warnings are highlighted:

- **ERRORS** indicate serious issues that likely need to be fixed before installation or that could cause problems afterward.
- **WARNINGS** highlight potential issues or settings that might be suboptimal.

Detailed information, like pod status, will be shown after related errors or warnings.

### Check Summary
HITT performs various checks depending on the mode and gathered information:

- Verifying required tools in the PATH
- Checking the KUBECONFIG file
- Checking namespaces and reporting unhealthy pods
- Discovering installed product versions
- Getting Helix Platform registry and RSSO details
- Validating the SSO realm configuration
- Reading IS details from Kubernetes and Jenkins
- Validating IS configuration settings, cacerts, and FTS Elastic settings
- Connecting to the IS database to query the current version
- Checking IS server license status and the Support Assistant Tool deployment

All tests are read-only and won't change the system. However, some checks deploy and delete temporary jobs/pods in the same way the Jenkins HELIX_ITSM_INTEROPS pipeline does.
