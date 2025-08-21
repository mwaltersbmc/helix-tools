#!/bin/bash
# Shell script to create a config file suitable for the tctl command line tool
# Should be run on a system with kubectl access to namespace being used
# Usage: ./generate_tctl_config.sh <ADE_NAMESPACE>
# Outputs config file contents to stdout suitable for copy/past or redirection
if [ $# -ne 1 ]; then
  echo "Usage: ./generate_tctl_config.sh <ADE_NAMESPACE>"
  exit 1
fi

# Expect $1 to be the namespace where the Helix Platform services are running
NAMESPACE="$1"
if [ -t 1 ]; then
  echo "Checking for Helix Platform TMS pods in ${NAMESPACE} namespace..."
fi

TMSPODCOUNT=$(kubectl -n ${NAMESPACE} get pod -l app=tms | wc -l)
if [ $TMSPODCOUNT -eq 0 ]; then
  >&2 echo "ERROR - Helix Platform TMS pods not found in ${NAMESPACE} namespace."
  exit 1
fi

>&2 echo "Getting data from TMS..."
# If tms-realm-admin secret exists (v23 onwards) we should use it otherwise use the tms-superuser-job
if kubectl get secret -n ${NAMESPACE} tms-realm-admin 2>&1 >/dev/null; then
  USER=$(kubectl get secret -n ${NAMESPACE} tms-realm-admin -o jsonpath='{.data.local_username}' | base64 -d)
  PASSWD=$(kubectl get secret -n ${NAMESPACE} tms-realm-admin -o jsonpath='{.data.local_password}' | base64 -d)
else
  USER=$(kubectl get job -n ${NAMESPACE} tms-superuser-job -o=jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="LOCAL_USER_NAME")].value}')
  PASSWD=$(kubectl get job -n ${NAMESPACE} tms-superuser-job -o=jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="LOCAL_USER_PASSWORD")].value}')
fi

# Get the config file values
TMS_URL=$(kubectl -n ${NAMESPACE} get deployment tms -o=jsonpath='{.spec.template.spec.containers[?(@.name=="tms")].env[?(@.name=="ADE_PLATFORM_BASE_URL")].value}')
APPURL=${TMS_URL%/*}
CLIENTID=$(kubectl -n ${NAMESPACE} get secret tms-auth-proxy-secret -o jsonpath='{.data.clientid}' | base64 -d -w 0)
CLIENTSECRET=$(kubectl -n ${NAMESPACE} get secret tms-auth-proxy-secret -o jsonpath='{.data.clientsecret}' | base64 -d -w 0)
RSSOURL=$(kubectl -n ${NAMESPACE} get cm rsso-admin-tas -o jsonpath='{.data.rssourl}{"/rsso\n"}')

>&2 echo -e "RSSO credentials are ${USER}/${PASSWD}"
echo "
appurl: ${APPURL}
clientid: ${CLIENTID}
clientsecret: ${CLIENTSECRET}
enableauth: true
rssourl: ${RSSOURL}
"
