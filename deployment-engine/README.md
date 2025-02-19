This repository contains a number of ansible playbooks to set up and configure a RHEL/Rocky 9.x system as a BMC Helix Deployment Engine.  This is an alternative to the Perl set up script that is part of the Helix Service Management applications.

Requirements

You will need a RHEL/Rocky 9.x system with:
- git and ansible-core <= 2.15
- ansible community.general and ansible.posix collections
- a valid kubeconfig file for your Kubernetes cluster
- the Helix Service Management git repository and plugins.txt files
- able to run the playbooks as the root user

Preparation

Start by downloading the playbook files with

# git clone https://github.com/mwaltersbmc/helix-tools

Copy the following files to the helix-tools/deployment-engine directory:
- the Helix Service Management git files - eg BMC_Remedy_Deployment_Manager_Configuration_Release_23.3.04.zip and LIBRARY_REPO.zip
- the plugins.txt file from the Helix Service Management Deployment Engine Setup zip file
- a valid kubeconfig file for your cluster - it must be named kubeconfig

Edit the 00-variables.yaml file and update the variables to match your requirements.  It is recommended to use the defaults unless there is a good reason not to.  You can choose to install the required software manually by setting the relevant options to false.

The playbooks

00-variables.yaml         common settings used by all the playbooks
01-create-users.yaml      creates the git and jenkins users, sets up ssh, and prepares the deployment files
02-install-software.yaml  installs the required OS tools
03-install-jenkins.yaml   installs the Jenkins application
04-configure-jenkins.yaml configures Jenkins to act as the Helix Service Management Deployment Engine
