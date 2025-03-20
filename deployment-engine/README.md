This repository contains a number of ansible playbooks to set up and configure a RHEL/Rocky 9.x system as a BMC Helix Deployment Engine.  This is an alternative to the Perl script that is provided with the Helix Service Management applications.  Each playbook may be run independently if, for example, the tasks covered by a previous playbook have already been completed.

Many of the steps, such as creating users and installing software, require elevated permissions so the playbooks are expected to be run as the root user.

### Requirements

You will need a RHEL/Rocky 9.x system with:
- git and ansible-core <= 2.15
- ansible community.general and ansible.posix collections (use **ansible-galaxy install -r requirements.yaml** to install them)
- a valid kubeconfig file for your Kubernetes cluster
- the Helix Service Management git repository zip and plugins.txt files
- root access

### Preparation

Start by downloading the playbook files with:

```sh
git clone https://github.com/mwaltersbmc/helix-tools
```

Change to, and copy the following files to, the **helix-tools/deployment-engine** directory:
- the Helix Service Management git repos zip files - eg BMC_Remedy_Deployment_Manager_Configuration_Release_23.3.04.zip and LIBRARY_REPO.zip
- the **plugins.txt** file from the Helix Service Management Deployment Engine Setup zip file
- a valid **kubeconfig** file for your cluster - it must be named kubeconfig

### The Playbooks

| File | Description |
| --- | ----------- |
| 00-variables.yaml | Common settings used by all the playbooks |
| 01-create-users.yaml | Creates the git and jenkins users, sets up ssh, and prepares the deployment files |
| 02-install-software.yaml | Installs the required OS tools |
| 03-install-jenkins.yaml | Installs the Jenkins application |
| 04-configure-jenkins.yaml | Configures Jenkins to act as the Helix Service Management Deployment Engine |
| 99-reset.yaml | Uninstalls Jenkins and deletes the git and jenkins users |

If you encounter an error when running a playbook you should be able to correct the issue and rerun without having to undo any completed steps.

### Usage

Start by editing the **00-variables.yaml** file and updating the values to match your requirements.  It is recommended that you use the defaults unless there is a good reason to change them.  

If you are using a freshly installed system, run the playbooks in numerical order to create and configure the users, install software, and set up Jenkins.  Once completed you should be able to login to Jenkins using the **jenkins_login_\*** credentials set in the variables file.  All of the deployment pipelines should be present, along with a job called **01 - Dry run build of all Helix deployment pipelines**, which will dry run the Helix jobs and prepare them for use.  All of the other Jenkins configuration steps - global libraries, credential creation, etc - have been done by the playbooks.  Once the dry runs are complete you are ready to start the Helix deployments.

### Jenkins Validation

You can use the **HITT** script with the **-m jenkins** option to check that Jenkins is ready for use.  Review the README file in the **helix-tools/hitt** folder for more details.
