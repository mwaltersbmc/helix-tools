The Helix IS Triage Tool (aka HITT) is a shell script that tests for many common configuration problems that may cause issues during installation and use of Helix IS Service Management applications.  The script should be run as the git user on the Deployment Engine system where Jenkins is installed.

HITT has three operating modes, all of which require that the Helix Platform installation has been completed.

**post-hp**	- used after the Helix Platform has been installed and the SSO realm for Helix IS has been created.\
**pre-is**	- used when the Jenkins HELIX_ONPREM_DEPLOYMENT and HELIX_GENERATE_CONFIG pipelines have been run with all the required parameters populated.\
**post-is**	- used after the installation of Helix IS has been completed.

In all modes the HITT script requires minimal configuration and will read additional information from Kubernetes, Jenkins and the CUSTOMER_CONFIGS git repository.

There are additional, optional, tests that will attempt to validate the Helix IS database that require the use of a Java SQL client called JISQL, and JDBC drivers for each database type.  To enable these tests, download the dbjars.tgz file and save it in the same directory as the hitt.sh script.  HITT will detect, unpack, and enable the SQL checks when this file is present.

**Installation**

Log in as the git user, create a new directory, cd to it and download the script and, if required, the dbjars.tgz file.

```
$ mkdir hitt
$ cd hitt
$ wget https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh
$ wget https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz
```

**Configuration**

HITT is configured by a file called hitt.conf which will be created the first time the script is run. If you need to change any values after the first run, either delete or edit this file and enter the four required variables manually. There is also a section where you can enter details about Jenkins.  This may be left as-is unless your Jenkins requires credentials or is running on a non-default port. If your Jenkins password includes special characters enclose the value in double quotes.

```
# First run to configure HITT
$ bash -m hitt.sh
```
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
JENKINS_USERNAME=
JENKINS_PASSWORD=
JENKINS_HOSTNAME=localhost
JENKINS_PORT=8080
```

Finally, there is a section for the command line tools which the script uses.  It is assumed that these are installed and available in directories that are included in the PATH environment variable of the user running the script.  HITT will check that these tools are present and report any that can't be found.  Missing tools must be installed, or the full path to their location set if they are not on the PATH.

**Running HITT**

Run the script using bash or make it executable with chmod if preferred.

```
$ bash hitt.sh
OR
$ chmod a+x hitt.sh
$ ./hitt.sh
```

HITT requires one command line option (-m) to specify the operating mode and will print a usage message if this is not provided.

```
$ bash hitt.sh
Helix IS Triage Tool (HITT)
Usage: bash hitt.sh -m <post-hp|pre-is|post-is> [-f HITT_CONFIG_FILE]

Examples:
bash hitt.sh -m post-hp  - run post HP installation only checks
OR
bash hitt.sh -m pre-is   - run IS pre-installation checks
OR
bash hitt.sh -m post-is  - run IS post-installation checks
```

Use post-hp after successfully installing the Helix Platform but before using Jenkins.
Use pre-is after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS.
Use post-is for troubleshooting after IS deployment.
Optional -f to use a different config file.

HITT will print the results of the checks and tests as they are run.  Errors and warnings are noted with highlighted messages.

<span style="color:red">ERRORS</span> indicate problems which likely need to be addressed before installation will be successful or may be the cause of problems post-install.\
<span style="color:yellow">WARNINGS</span> highlight potential problems or settings which may be appropriate under some conditions but are usually recommended to be different.

Where the test being run includes additional output, pod status for example, this is displayed after the related ERROR or WARNING.

All of the tests are read-only and will not make changes to the system.  However, please note that the checks which discover the tenant and service details from the Helix Platform deploy a tctl job/pod in the same way as the Jenkins HELIX_ITSM_INTEROPS pipeline.  The job/pod are deleted after use.

**Checks Summary**

Not all groups of checks are run, and some run different tests, depending on the operating mode and discovered information.  Some groups query information which is then used by other checks.

Checking for required tools in path...
	Verify that the required command line tools and versions are available.

Checking KUBECONFIG file...
  Tests that a valid kubeconfig file is present or configured via the KUBECONFIG environment variable.

Checking namespaces...
  Tests that namespaces exist, are of the expected type, and reports unhealthy pods.

Getting versions...
  Discovers versions of installed products.

Getting Helix Platform registry details from bmc-dtrhub secret...
Getting RSSO details...
Getting domain...
	Configuration discovery from the Helix Platform.

Getting tenant details from Helix Platform...
  Discovers tenant data and will offer a selection menu if a multi-tenant platform is found.

Checking for ITSM services in Helix Platform...
  Checks that the ARSERVICES option was enabled during Helix Platform installation.

Checking FTS Elasticsearch cluster status...
  Checks the health of the Elasticsearch instance used for FTS.

Getting realm details from RSSO...
  Reports SSO realm details.

Validating realm...
  Verifies that the SSO realm has been configured with the expected tenant, Application Domains and authentication details.

Getting IS details...
  Reads IS details from Kubernetes/Jenkins.

Validating IS details...
  Tests IS config settings.

Validating IS cacerts...
  Tests the cacerts file from Jenkins or namespace to make sure it has the required certificates.

Checking IS FTS Elastic settings...
  Validation of FTS specific settings.

Checking IS DB settings...
	Attempts to connect to the IS database and query the currDbVersion from the control table.

Checking IS license status...
  IS Server license status.

Checking Support Assistant Tool...
  If deployed, are the sidecar containers and required permissions present.
