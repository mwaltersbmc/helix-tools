The Helix IS Triage Tool (**HITT**) is a shell script that tests for many common configuration problems that cause issues during the installation and use of Helix IS Service Management applications.  The script should be run as the git user on the Deployment Engine system where Jenkins is installed.

HITT has three main operating modes and a tctl command option, all of which require that the Helix Platform installation has been completed.

The main modes are:

**post-hp**	- used after the Helix Platform has been installed and the SSO realm for Helix IS has been created.\
**pre-is**	- used after the Jenkins HELIX_ONPREM_DEPLOYMENT and HELIX_GENERATE_CONFIG pipelines have been run with all the installation values populated.\
**post-is**	- used after the installation of Helix IS has been completed.

The HITT script requires minimal manual configuration and will read the information it needs from Kubernetes, Jenkins, and the CUSTOMER_CONFIGS git repository.

There are some optional tests that will attempt to validate the Helix IS database.  These require the use of a Java SQL client, called JISQL, and JDBC drivers for each database type.  To enable these tests, download the dbjars.tgz file and save it in the same directory as the hitt.sh script.  HITT will run the SQL checks when this file is present.

### Installation ###

Log in as the git user, create a new directory, cd to it and download the script along with, if required, the dbjars.tgz file.

```
$ mkdir hitt
$ cd hitt
$ wget https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh
$ wget https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz
```

### Configuration ###

HITT is configured by a file called **hitt.conf** which is created the first time the script is run. If you need to change any values after the first run, delete or edit this file and enter the four required variables manually. There is also a section where you can enter details about your Jenkins which may be left as-is unless it requires credentials, uses https, or is running on a non-default port. Enclose the **JENKINS_USERNAME** and **JENKINS_PASSWORD** values in double quotes.  If your Jenkins is configured to use SSL change the **JENKINS_PROTOCOL** to **https** and set the **JENKINS_PORT** appropriately.

```
# First run to configure HITT
$ bash hitt.sh
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
JENKINS_PROTOCOL=http
JENKINS_PORT=8080
```

Finally, there is a section for the command line tools that the script uses.  It is assumed that these are installed and available in directories that are included in the PATH environment variable of the user running the script.  HITT will check that these tools are present and report any that can't be found.  Missing tools must be installed, or the full path to their location set, if they are not in the PATH.

### Running HITT ###

Run the script using bash or make it executable with chmod if preferred.

```
$ bash hitt.sh
OR
$ chmod a+x hitt.sh
$ ./hitt.sh
```

HITT requires one command line option (-m) to specify the operating mode, unless being used for tctl commands, and will print a usage message if this is not provided.

```
$ bash hitt.sh
Helix IS Triage Tool (HITT)
Usage: bash hitt.sh -m <post-hp|pre-is|post-is>

Examples:
bash hitt.sh -m post-hp  - run post HP installation only checks
OR
bash hitt.sh -m pre-is   - run IS pre-installation checks
OR
bash hitt.sh -m post-is  - run IS post-installation checks
```

Use **post-hp** after installing and configuring the Helix Platform but before using Jenkins.\
Use **pre-is** after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting the deployment of Helix IS.\
Use **post-is** for troubleshooting after IS deployment.

HITT will print the results of the checks and tests as they are run.  Errors and warnings are noted with highlighted messages and summarised at the end.  A **hittmgs.log** file is created which contains more detailed information, including the impact and suggested fix, for each error/warning.

<span style="color:red">ERRORS</span> indicate problems which may cause installation to fail or result in problems post-install.\
<span style="color:yellow">WARNINGS</span> highlight potential problems or settings which may be appropriate under some conditions, but are usually recommended to be different.

When the test being run produces additional output, pod status for example, this is displayed after the related ERROR or WARNING.

All of the tests are read-only and will not make changes to the system.  However, please note that the checks which discover the tenant and service details from the Helix Platform deploy a tctl job/pod in the same way as the Jenkins HELIX_ITSM_INTEROPS pipeline.  The job/pod are deleted after use.

### Logging ###

HITT creates various log files in the directory that the script is run from:

- **hittmsgs.log** - additional details on the cause, impact and steps to fix, warnings and errors reported by the script.
- **hitt.log** - script output.
- **values.log** - the pipeline input values in pre-is mode, or values read from the cluster for post-is.
- **PIPELINE_NAME.log** - console output for each of the Jenkins pipelines.
- **k8s\*.log** - output from various kubectl commands such as 'get pods'.
- **hittdebug.log** - error messages from commands run by the script which may be useful if it does not work as expected.

All of the files are added to **hittlogs.zip** which can be sent to BMC Support if needed.

There are some additional messages which are not logged by default but can be enabled with the **-v** switch.

**NOTE** - passwords are not logged unless the **-p** switch is used.

### tctl Mode ###

HITT may also be used to run simple **tctl** commands such as **get tenant** and **get service**.  This deploys the same job and pod used by the Jenkins HELIX_ITSM_INTEROPS pipeline and avoids having to download and configure the tctl client on a local system.  The command uses the **-t** switch:

```
$ bash hitt.sh -t "tctl command"
Examples:
$ bash hitt.sh -t "get tenant"
$ bash hitt.sh -t "get tenant 1912102789 -o json"
```

The tctl commands must be enclosed in double quotes and the output will be displayed on the console when the job completes.

### Advanced CLI Options ###

There are several extra command line switches which may be helpful for troubleshooting.

-c&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Do not remove temporary files used by HITT.\
-d&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enable *set -x* debugging output.\
-e #&nbsp;&nbsp;&nbsp;&nbsp;Script will exit on specified error number.  Use *-e 0* to stop on first error.\
-j&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Display the Jenkins credentials details and save kubeconfig contents as kubeconfig.jenkins.\
-p&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;In pre-is mode, output pipeline passwords in *values.log* file.\
-v&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Increase verbosity of logging,

### Checks Summary ###

Different groups of tests and checks are run depending on the operating mode and discovered information.  Some groups query information which is then used by other checks.

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
