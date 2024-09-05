# BMC Helix SEAL-Pipelines for Jenkins

This is a collection of utility and troubleshooting pipeline jobs for the Jenkins server running on the BMC Helix Deployment Engine.  They are installed using Ansible and will be shown in Jenkins in a **SEAL-Pipelines** folder.

## Pipelines
| Pipeline Name            |Description
|----------------|-------------------------------
|DE - Install K8s Clients | Installs/upgrades K8s clients and tools
|DE - Run kubectl Command | Run `kubectl` commands from the Deployment Engine
|HP - Run tctl Command | Run `tctl` commands for the Helix Platform
|IS - Apply IS Server License | Apply an IS server license via the RESTAPI
|IS - Create Realm in SSO | Creates a realm for Helix IS in the Helix Platform SSO
|IS - Generate DBID for IS Server | Generate the DB ID used for IS licensing
|IS - Save cacerts in ITSM_REPO | Save updated cacerts file to git ITSM_REPO

## Installing the Pipelines

Start by using git to download the **seal-pipelines** files to a directory that is accessible to the **git-user** that installed Jenkins. For example:

```sh
cd /home/git
git clone https://github.com/mwaltersbmc/helix-tools
cd helix-tools/seal-pipelines
```

The pipelines are installed using the **create-pipelines.yaml** Ansible playbook.  There are several options that can be set by editing the playbook or passing values on the command line. The default values are:

jenkins_username: ""\
jenkins_password: ""\
jenkins_port: 8080 \
pipelines_foldername: "SEAL-Pipelines"

The username and password are required if your Jenkins has authentication enabled, otherwise they can be left as "".  The **pipelines_foldername** is the name of the folder in Jenkins where the pipelines will be created and the **jenkins_port** is the port used for accessing Jenkins.

Update and save the file or pass the values when running the playbook using the **-e** option, for example:
```sh
ansible-playbook create-pipelines.yaml -e "jenkins_username=admin" -e "jenkins_password=mysecretpwd"
```

The playbook will create a new folder in Jenkins for the pipelines and it may be rerun to add or update pipelines if future versions are released.

## Pipeline Details

Output from the commands run by the pipelines will be available via the **Console Output**.

#### DE - Install K8s Clients
Installs or updates versions of `kubectl` and `helm` on the Deployment Engine with options to install additional useful tools.

| Parameter            |Description
|----------------|-------------------------------
|TARGET_DIR | The directory to install the tools in.  Requires use of `sudo` if not writable by the git user
|INSTALL_KUBECTL | Install `kubectl`?
|KUBECTL_VERISON | Version to install - see https://kubernetes.io/releases
|INSTALL_KUBECTL | Install `helm`?
|INSTALL_KUBECTL | Version to install - see https://github.com/helm/helm/releases
|INSTALL_KUBE_CAPACITY | Tool for reporting resource usage - see https://github.com/robscott/kube-capacity
|INSTALL_K9S | Terminal mode Kubernetes management tool - see https://k9scli.io

#### DE - Run kubectl Command
Runs `kubectl` commands:

| Parameter            |Description
|----------------|-------------------------------
|NAMESPACE | The Kubernetes namespace to run the command in, if required
|KUBECTL_COMMAND | The `kubectl` command to run - e.g. `get pod`

#### HP - Run tctl Command
Run the Helix Platform **tctl** tool using a job container to avoid having to download and configure it on the Deployment Engine.\
**NOTE:** Requires the ansible plugin to be installed in Jenkins.
| Parameter            |Description
|----------------|-------------------------------
|HELIX_PLATFORM_NAMESPACE | The Helix Platform namespace name
|TCTL_COMMAND | The `tctl`  command to run - e.g. get tenant.  Accepts JSON input strings

#### IS - Apply IS Server License
Uses the IS RESTAPI to add a server license.

| Parameter            |Description
|----------------|-------------------------------
|IS_NAMESPACE | The Helix IS namespace name
|AR_ADMIN_USER | The username of an IS administrator - defaults to Demo
|AR_ADMIN_PASSWORD | The password for the AR_ADMIN_USER user
|LICENSE_KEY | The IS license key
|EXPIRY_DATE | The expiry date if applying a temporary license

#### IS - Create Realm in SSO
Creates and configures the IS realm in the SSO server.  The pipeline will
- discover the RSSO credentials and CLUSTER_DOMAIN
- create the realm with the URLs generated using the CUSTOMER_SERVICE-ENVIRONMENT format
- configure AR Authentication

| Parameter            |Description
|----------------|-------------------------------
|HELIX_PLATFORM_NAMESPACE | The Helix Platform namespace name
|IS_NAMESPACE | The Helix IS namespace name
|CUSTOMER_SERVICE | The CUSTOMER_SERVICE value which will be used in the HELIX_ONPREM_DEPLOYMENT pipeline
|ENVIRONMENT | The ENVIRONMENT value which will be used in the HELIX_ONPREM_DEPLOYMENT pipeline

#### IS - Generate DBID for IS Server License
Displays the database ID, used for IS licensing, for the provided database connection values.

| Parameter            |Description
|----------------|-------------------------------
|DB_TYPE | The IS database type - postgres/mssl/oracle
|DATABASE_HOST_NAME | The database hostname used in the HELIX_ONPREM_DEPLOYMENT pipeline
|AR_DB_NAME | The name of the AR database - default is ARSystem

#### IS - Save cacerts in ITSM_REPO
Adds an updated cacerts file to the ITSM_REPO to avoid issues if the HELIX_ONPREM_DEPLOYMENT pipeline is run without attaching it.  The cacerts file may be located on the Deployment Engine or provided via the pipeline.

| Parameter            |Description
|----------------|-------------------------------
|ITSM_REPO_PATH | The path to the `ITSM_REPO/itsm-on-premise-installer.git` directory
|DE_CACERTS_FILE | The full path to the updated cacerts file if it is stored on the Deployment Engine
|LOCAL_CACERTS_FILE | Attach a cacerts file from local storage

## NOTES
- The pipeline jobs use ansible playbooks for most of their work and access the Deployment Engine using ssh in the same way as the BMC product pipelines.
- The **Install K8s Clients** pipeline requires the git user to be able to use `sudo` if the target location to save files is a system directory such as `/usr/local/bin`.  
- The **Run tctl Command** pipeline requires that the Ansible plugin is installed in Jenkins.  Install using `Manage Jenkins -> Plugins -> Available Plugins`
- Scripts may need approval via `Manage Jenkins -> In-process Script Approval` before they can be used.
