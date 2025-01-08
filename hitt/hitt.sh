#!/usr/bin/env bash

# Helix IS Triage Tool (HITT) shell script to validate settings for Helix onprem - pre and post deployment
# Mark Walters SEAL Team May '24

# FUNCTIONS Start

getConfValues() {
  logStatus "Please select your Helix Platform namespace..."
  HP_NAMESPACE=$(selectFromArray NS_ARRAY)
  logStatus "Please select your Helix IS namespace..."
  IS_NAMESPACE=$(selectFromArray NS_ARRAY)
  logStatus "Please enter your HELIX_ONPREM_DEPLOYMENT pipeline CUSTOMER_SERVICE and ENVIRONMENT values:"
  read -p "CUSTOMER_SERVICE : " IS_CUSTOMER_SERVICE
  read -p "ENVIRONMENT : " IS_ENVIRONMENT
  logStatus "Please enter your Jenkins username and password if required, otherwise just press return:"
  read -p "Username : " JENKINS_USERNAME
  read -s -p "Password : " JENKINS_PASSWORD
}

createHITTconf() {
  cat << EOF > "${1}"
# This is the config file for the Helix IS Triage Tool script.

# REQUIRED SETTINGS
# Enter your Helix namespace names and HELIX_ONPREM_DEPLOYMENT pipeline values for CUSTOMER_SERVICE and ENVIRONMENT
HP_NAMESPACE=${HP_NAMESPACE}
IS_NAMESPACE=${IS_NAMESPACE}
IS_CUSTOMER_SERVICE=${IS_CUSTOMER_SERVICE}
IS_ENVIRONMENT=${IS_ENVIRONMENT}

# OPTIONAL SETTINGS
# Set JENKINS credentials and hostname/port if required
# Use double quotes to avoid issues with special characters
JENKINS_USERNAME="${JENKINS_USERNAME}"
JENKINS_PASSWORD="${JENKINS_PASSWORD}"
JENKINS_HOSTNAME=localhost
JENKINS_PROTOCOL=http
JENKINS_PORT=8080

# Required Tools - set full path to binary if not present on path
KUBECTL_BIN=kubectl
CURL_BIN=curl
KEYTOOL_BIN=keytool
OPENSSL_BIN=openssl
JQ_BIN=jq
BASE64_BIN=base64
GIT_BIN=git
JAVA_BIN=java
TAR_BIN=tar
NC_BIN=nc
HOST_BIN=host
ZIP_BIN=zip
UNZIP_BIN=unzip
EOF
}

logError() {
  # Print error message MSG_ID MSG / exit if value of 1 passed as third parameter
  stopOnError "${1}"
  MSG="${BOLD}${RED}ERROR${NORMAL} (${1}) - ${2}"
  echo -e "${MSG}"
  ((FAIL++))
  ERROR_ARRAY+=("(${1}) - ${2}")
  logMessageDetails "${1}" "${MSG}"
  [[ ${3} == 1 ]] && exit 1
}

logWarning() {
  # Print warning message MSG_ID MSG
  stopOnError "${1}"
  MSG="${BOLD}${YELLOW}WARNING${NORMAL} (${1}) - ${2}"
  echo -e "${MSG}"
  ((WARN++))
  WARN_ARRAY+=("(${1}) - ${2}")
  logMessageDetails "${1}" "${MSG}"
}

logMessage() {
  # Print message
  echo -e "\t${1}"
}

logStatus() {
  echo -e "\n${BOLD}${1}${NORMAL}"
}

stopOnError() {
  if [ "${STOP_ON_ERROR}" == "${1}" ] || [ "${STOP_ON_ERROR}" == "0" ]; then
    exit
  fi
}

usage() {
    echo ""
    echo -e "${BOLD}Helix IS Triage Tool (HITT)${NORMAL}"
    echo -e "${BOLD}Usage: bash $0 -m <post-hp|pre-is|post-is>${NORMAL}"
    echo ""
    echo "Examples:"
    echo "bash $0 -m post-hp   - run post HP installation only checks"
    echo "OR"
    echo "bash $0 -m pre-is   - run pre-installation checks"
    echo "OR"
    echo "bash $0 -m post-is  - run post-installation checks"
    echo ""
    echo -e "Use ${BOLD}post-hp${NORMAL} after successfully installing the Helix Platform but before using Jenkins."
    echo -e "Use ${BOLD}pre-is${NORMAL} after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS."
    echo -e "Use ${BOLD}post-is${NORMAL} for troubleshooting after IS deployment."
    exit 1
}

checkVars() {
  if [ -z "${HP_NAMESPACE}" ] || [ -z "${IS_NAMESPACE}" ] || [ -z "${IS_CUSTOMER_SERVICE}" ] || [ -z "${IS_ENVIRONMENT}" ] ; then
    logError "100" "Please set the namespace and IS variables in the ${HITT_CONFIG_FILE} file." 1
  fi
}

checkRequiredTools() {
  for i in "${REQUIRED_TOOLS[@]}"; do
    BINARY="${i^^}_BIN"
    checkBinary "${!BINARY}" "${i}"
  done
  if [ $FAIL -gt 0 ] ; then
    exit 1
  fi
}

compare() (IFS=" "
  exec awk "BEGIN{if (!($*)) exit(1)}"
)

checkToolVersion() {
  case "${1}" in
    jq)
      REQUIRED_VERSION=1.6
      INSTALLED_VERSION=$(${JQ_BIN} --version | tr -d 'jq-')
      if compare "${INSTALLED_VERSION} < ${REQUIRED_VERSION}"; then
        logError "101" "jq version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed.  Please upgrade from https://jqlang.github.io/jq/download"
        FAIL=1
      fi
      ;;
    java)
      REQUIRED_VERSION=11
      INSTALLED_VERSION=$(${JAVA_BIN} -version 2>&1 | grep -oP 'version "?(1\.)?\K\d+')
      JAVA_VERSION="${INSTALLED_VERSION}"
      if compare "${INSTALLED_VERSION} < ${REQUIRED_VERSION}"; then
        logError "101" "java version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed."
        FAIL=1
      fi
      ;;
    kubectl)
      REQUIRED_VERSION=1.20
      KUBECTL_JSON=$(${KUBECTL_BIN} version -o json 2>>${HITT_DBG_FILE})
      INSTALLED_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.clientVersion.major + "." + .clientVersion.minor')
      KUBECTL_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.clientVersion.gitVersion')
      K8S_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.serverVersion.gitVersion')
      if compare "${INSTALLED_VERSION} < ${REQUIRED_VERSION}"; then
        logError "101" "kubectl version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed."
        FAIL=1
      fi
      ;;
    *)
      ;;
  esac
}

checkBinary() {
  if ! which "${1}" > /dev/null 2>&1 ; then
    logError "105" "${1} command not found in path. Please set ${BINARY} variable with the full path to the file."
  else
    logMessage "${1} command found ($(which ${1}))."
    checkToolVersion "${2}"
  fi
}

cleanUp() {
  if [ ! -z "${SKIP_CLEANUP}" ]; then return; fi
  if [ "${1}" == "start" ]; then
      CLEANUP_FILES_TO_RM=("${CLEANUP_FILES[@]}" "${CLEANUP_START_FILES[@]}")
  fi
  if [ "${1}" == "stop" ]; then
      CLEANUP_FILES_TO_RM=("${CLEANUP_FILES[@]}" "${CLEANUP_STOP_FILES[@]}")
  fi
  for i in "${CLEANUP_FILES_TO_RM[@]}"; do
    rm -f ${i}
  done
  for i in "${CLEANUP_DIRS[@]}"; do
    rm -rf ${i}
  done
}

generateRandom() {
  STRING=""
  for i in {0..7}; do
    STRING+=$(printf "%x" $(($RANDOM%16)) );
  done
  echo "${STRING}"
}

checkK8sAuth() {
  if ${KUBECTL_BIN} auth can-i ${1} ${2} > /dev/null 2>&1 ; then
    return 0
  else
    return 1
  fi
}

checkNamespaceExists() {
  if checkK8sAuth get ns; then
  # namespace_name - exit if not found
    if ! ${KUBECTL_BIN} get ns "${1}" > /dev/null 2>&1 ; then
      logError "106" "${NS_TYPE} namespace ${1} not found." 1
    else
      logMessage "${NS_TYPE} namespace ${1} found."
      checkNSResourceQuotas "${1}"
    fi
  else
    logWarning "001" "Unable to run 'kubectl get ns' - skipping namespace validation."
  fi
}

checkHPNamespace() {
  # namespace_name
  DEPLOYMENT=rsso
  NS_TYPE="Helix Platform"
  checkNamespaceExists "${1}"
    if ! ${KUBECTL_BIN} -n "${1}" get deployment "${DEPLOYMENT}" > /dev/null 2>&1 ; then
    logError "107" "Deployment ${DEPLOYMENT} not found in ${1} - please check the ${NS_TYPE} namespace name." 1
  else
    logMessage "${1} is a valid ${NS_TYPE} namespace."
  fi
  checkPodStatus "${1}"
}

checkISNamespace() {
  # namespace_name
  DEPLOYMENT=midtier-user
  NS_TYPE="Helix IS"
  checkNamespaceExists "${1}"
  if [ "${MODE}" == "pre-is" ]; then
    if [ $(${KUBECTL_BIN} -n "${1}" get secret --field-selector type=kubernetes.io/dockerconfigjson 2>&1 | wc -l) == "1" ]; then
      logError "108" "Registry secret not found in ${1} namespace - HELIX_GENERATE_CONFIG pipeline must have been run before ${MODE} checks." 1
    fi
  fi
  if [ "${MODE}" == "post-is" ]; then
    if ! ${KUBECTL_BIN} -n "${1}" get deployment "${DEPLOYMENT}" > /dev/null 2>&1 ; then
      logError "107" "Deployment ${DEPLOYMENT} not found in ${1} - please check the ${NS_TYPE} namespace name." 1
    fi
  fi
  logMessage "${1} appears to be a valid ${NS_TYPE} namespace."
  checkPodStatus "${1}"
}

checkPodStatus() {
  if [ $(${KUBECTL_BIN} -n "${1}"  get pods -o custom-columns=":metadata.name,:status.containerStatuses[*].state.waiting.reason" | grep -v "<none>" | wc -l) != "1" ]; then
     logError "102" "One or more pods in namespace ${1} found in a non-ready state."
     ${KUBECTL_BIN} -n "${1}" get pods -o custom-columns="POD:metadata.name,STATE:status.containerStatuses[*].state.waiting.reason" | grep -v "<none>"
  else
    logMessage "No unhealthy pods found in ${1} namespace."
  fi
}

getVersions() {
  logMessage "Kubernetes version ${K8S_VERSION}."
  logMessage "kubectl version ${KUBECTL_VERSION}."
  if [ -f /etc/os-release ]; then
    OS_NAME=$(grep "^NAME=" /etc/os-release | cut -d '=' -f2)
    OS_VERSION=$(grep "^VERSION=" /etc/os-release | cut -d '=' -f2)
    logMessage "Running on ${OS_NAME} version ${OS_VERSION}."
  fi
  HP_CONFIG_MAP_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm helix-on-prem-config -o json)
  HP_VERSION=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.version' | head -1)
  HP_DEPLOYMENT_SIZE=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.deployment_config' | grep ^DEPLOYMENT_SIZE | cut -d '=' -f2)
  logMessage "Helix Platform version - ${HP_VERSION} using DEPLOYMENT_SIZE ${HP_DEPLOYMENT_SIZE}."
  if [[ ! "${HP_DEPLOYMENT_SIZE}" =~ ^itsm.* ]]; then
    logWarning "002" "Helix Platform DEPLOYMENT_SIZE is ${HP_DEPLOYMENT_SIZE} - expected to be itsmcompact/itsmsmall/itsmxlarge unless additional ITOM products to be installed."
  fi

  if [ "${MODE}" == "post-is" ]; then
    IS_VERSION=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.metadata.labels.chart}' | cut -f2 -d '-')
    logMessage "Helix IS version - ${IS_VERSION}."
    # Set expected currDBVersion
    case "${IS_VERSION%%.*}" in
      21)
        IS_DB_VERSION=199
        ;;
      22)
        IS_DB_VERSION=200
        ;;
      23)
        [[ "${IS_VERSION}" == "23.3.03" ]] && IS_DB_VERSION=201
        [[ "${IS_VERSION}" == "23.3.04" ]] && IS_DB_VERSION=203
        ;;
      25)
        IS_DB_VERSION=202
        ;;
      *)
        logError "109" "Unknown Helix IS version (${IS_VERSION}) - please check https://bit.ly/gethitt for HITT updates." 1
    esac
  fi
}

checkNSResourceQuotas() {
  # NS name
  if [ $(${KUBECTL_BIN} -n "${1}" get resourcequotas 2>/dev/null | wc -l) != "0" ]; then
    logWarning "034" "Resource quotas are set in the '${1}' namespace. See k8s-get-resourcequotas-${1}.log file for details."
    ${KUBECTL_BIN} -n "${1}" get resourcequotas -o yaml > k8s-get-resourcequotas-${1}.log
  fi
}

setVarsFromPlatform() {
  FTS_ELASTIC_CERTNAME="esnode"
  EFK_ELASTIC_SERVICENAME="efk-elasticsearch-data-hl"
  LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress helixingress-master -o jsonpath='{.spec.rules[0].host}')
  TMS_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress tms-ingress -o jsonpath='{.spec.rules[0].host}')
  MINIO_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress minio -o jsonpath='{.spec.rules[0].host}')
  MINIO_API_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress minio-api -o jsonpath='{.spec.rules[0].host}')
  KIBANA_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress efk-elasticsearch-kibana -o jsonpath='{.spec.rules[0].host}')
  LOG_ELASTICSEARCH_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret logelasticsearchsecret -o jsonpath='{.data}')
  FTS_ELASTIC_SERVICENAME=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_CLUSTER | @base64d' | cut -d ':' -f 1)
  LOG_ELASTICSEARCH_PASSWORD=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_PASSWORD | @base64d')
  LOG_ELASTICSEARCH_USERNAME=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_USERNAME | @base64d')
  FTS_ELASTIC_POD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get endpoints "${FTS_ELASTIC_SERVICENAME}" -o=jsonpath='{.subsets[*].addresses[0].ip}' | xargs -I % ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pods --field-selector=status.podIP=% -o jsonpath='{.items[0].metadata.name}')

  # Catch cases where the LB_HOST is the same as the IS CUSTOMER_SERVICE-ENVIRONMENT.CLUSTER_DOMAIN
  if [ "${IS_ENVIRONMENT}" == "prod" ]; then
    IS_PREFIX="${IS_CUSTOMER_SERVICE}"
  else
    IS_PREFIX="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
  fi
  for i in LB_HOST TMS_LB_HOST MINIO_LB_HOST MINIO_API_LB_HOST KIBANA_LB_HOST; do
    if [ "${!i}" == "${IS_PREFIX}.${LB_HOST#*.}" ]; then
      logError "110" "${i} value '${!i}' conflicts with the derived MidTier alias '${IS_PREFIX}.${LB_HOST#*.}'."
      #logError "You ${BOLD}MUST${NORMAL} change one or more of the Helix Platform LB_HOST, Helix IS CUSTOMER_SERVICE or ENVIRONMENT before installing Helix IS."
    fi
  done

  if [[ "${FTS_ELASTIC_SERVICENAME}" =~ ^opensearch.* ]]; then
    FTS_ELASTIC_POD_CONTAINER="-c opensearch"
  fi

  case "${HP_VERSION}" in
    22.2.01)
      TCTL_VER=110
      ADE_INFRA_CLIENT_IMAGE_TAG=22201-1-v4-ade-infra-clients-1
      ;;
    22.4)
      TCTL_VER=230
      ADE_INFRA_CLIENT_IMAGE_TAG=22400-v9-ade-infra-clients-1
      ;;
    23.1.02)
      TCTL_VER=255
      ADE_INFRA_CLIENT_IMAGE_TAG=23102-v3-ade-infra-clients-1
      ;;
    23.2.02)
      TCTL_VER=310
      ADE_INFRA_CLIENT_IMAGE_TAG=23202-v1-ade-infra-clients-1
      ;;
    23.4.00)
      TCTL_VER=370
      ADE_INFRA_CLIENT_IMAGE_TAG=23400-v2-ade-infra-clients-1
      ;;
    24.1.00)
      TCTL_VER=420
      ADE_INFRA_CLIENT_IMAGE_TAG=24100-v5-ade-infra-clients-1
      ;;
    24.2.00)
      TCTL_VER=472
      ADE_INFRA_CLIENT_IMAGE_TAG=24200-v6-ade-infra-clients-alpine
      ;;
    24.3.00)
      TCTL_VER=529
      ADE_INFRA_CLIENT_IMAGE_TAG=24300-v46-ade-infra-clients-alpine
      ;;
    24.4.00)
      TCTL_VER=574
      ADE_INFRA_CLIENT_IMAGE_TAG=24400-v71-ade-infra-clients-alpine
      ;;
    25.1.00)
      TCTL_VER=602
      ADE_INFRA_CLIENT_IMAGE_TAG=25100-v97-ade-infra-clients-alpine
      ;;
    *)
      ;;
  esac

  HP_COMPANY_NAME_LABEL="COMPANY_NAME"
  if compare "${HP_VERSION%.*} >= 24.2" ; then
    HP_COMPANY_NAME_LABEL="TENANT_NAME"
  fi

  if [ "${HP_VERSION}" == "24.2.00" ] ; then
    ADE_CS_OK=0
    if ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment credential > /dev/null 2>&1; then
      ADE_CS_OK=1
    else
      ADE_CS_ENABLED=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment tms -o jsonpath='{.spec.template.spec.containers[?(@.name=="tms")].env[?(@.name=="ADE_CS_ENABLED")].value}')
      [[ ! -z "${ADE_CS_ENABLED}" ]] && ADE_CS_OK=1
    fi
    [[ "${ADE_CS_OK}" == "0" ]] && logError "111" "The Helix Platform credential service is not installed or disabled in the TMS deployment.  Please see the 'Known and corrected issues' documentation."
  fi

  if compare "${HP_VERSION%.*} >= 24.3" ; then
    FTS_ELASTIC_CERTNAME="esnodeopensearch2"
  fi
}

getRSSODetails() {
  RSSO_ADMIN_TAS_CM=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm rsso-admin-tas -o json)
  RSSO_URL=$(echo "$RSSO_ADMIN_TAS_CM" | ${JQ_BIN} -r '.data.rssourl + "/rsso"')
  logMessage "RSSO URL is ${RSSO_URL}."
  RSSO_USERNAME=$(echo "$RSSO_ADMIN_TAS_CM" | ${JQ_BIN} -r '.data.username')
  logMessage "RSSO username is ${RSSO_USERNAME}."
  RSSO_PASSWORD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret rsso-admin-tas -o jsonpath='{.data.password}' | ${BASE64_BIN} -d)
  RSSO_TOKEN_JSON=$(${CURL_BIN} -sk -X POST "${RSSO_URL}"/api/v1.1/admin/login -H 'Content-Type: application/json' -d '{"username":"'"${RSSO_USERNAME}"'","password":"'"${RSSO_PASSWORD}"'"}')
  if [[ "${RSSO_TOKEN_JSON}" =~ "admin_token" ]]; then
    RSSO_TOKEN=$(echo "${RSSO_TOKEN_JSON}" | ${JQ_BIN} -r .admin_token)
    logMessage "RSSO login OK - got admin token."
  else
    logError "112" "Unable to get the RSSO admin token. RSSO response: ${RSSO_TOKEN_JSON}" 1
  fi
}

getDomain() {
  CLUSTER_DOMAIN=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment tms -o jsonpath='{.spec.template.spec.containers[?(@.name=="tms")].env[?(@.name=="DOMAIN_NAME")].value}')
  logMessage "Helix domain is ${CLUSTER_DOMAIN}."
}

checkHelixLoggingDeployed() {
  HELIX_LOGGING_DEPLOYED=0
  if ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment efk-elasticsearch-kibana > /dev/null 2>&1 ; then
    HELIX_LOGGING_DEPLOYED=1
    logMessage "Helix Logging is installed."
    HELIX_LOGGING_PASSWORD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret efk-elasticsearch-kibana -o jsonpath='{.data.kibana-password}' | ${BASE64_BIN} -d)
    checkEFKClusterHealth
  else
    logMessage "Helix Logging is not installed."
    if ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm helix-on-prem-config -o jsonpath='{.data.bmc_helix_logging_config}' | grep -q 'ENABLE_LOG_SHIPPER_IN_PODS=true'; then
      logWarning "003" "ENABLE_LOG_SHIPPER_IN_PODS=true - consider installing Helix Logging to reduce error messages in Helix Platform pod logs."
    fi
  fi
}

checkEFKClusterHealth() {
  EFK_ELASTIC_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" ${FTS_ELASTIC_POD_CONTAINER} -- sh -c 'curl -sk -u elastic:"'"${HELIX_LOGGING_PASSWORD}"'" -X GET https://"'"${EFK_ELASTIC_SERVICENAME}"'":9200/_cluster/health')
  EFK_ELASTIC_STATUS=$(echo "${EFK_ELASTIC_JSON}" | ${JQ_BIN} -r '.status')
  if ! echo "${EFK_ELASTIC_STATUS}" | grep -q green ; then
    logError "113" "Helix Logging Elasticsearch problem. Check the ${EFK_ELASTIC_SERVICENAME} pods in Helix Platform namespace."
  else
    logMessage "Helix Logging Elasticsearch (${EFK_ELASTIC_SERVICENAME}) appears healthy."
  fi
}

getTenantDetails() {
  TENANT_JSON=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/tenant -H "Authorization: RSSO ${RSSO_TOKEN}" | ${JQ_BIN} .tenants)
  TENANT_ARRAY=($(echo "${TENANT_JSON}" | ${JQ_BIN} -r .[].name | grep -v SAAS_TENANT))
  if [ "${#TENANT_ARRAY[@]}" == "0" ]; then
    logError "114" "No tenants, or only the SAAS_TENANT, found in SSO. Please review the Helix Platform deployment.log." 1
  fi
  if [ "${#TENANT_ARRAY[@]}" != "1" ]; then
#    echo "${TENANT_ARRAY}"
    logMessage "Multiple tenants found - please select the tenant you wish to use:"
    while [ "${HP_TENANT}" == "" ]; do
        HP_TENANT=$(selectFromArray TENANT_ARRAY)
    done
  else
    HP_TENANT="${TENANT_ARRAY[0]}"
  fi
  logMessage "Helix Platform tenant is ${HP_TENANT}."
  PORTAL_HOSTNAME=$(echo "${TENANT_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${HP_TENANT}'").host')
  logMessage "Helix Portal hostname is ${PORTAL_HOSTNAME}."
  HP_COMPANY_NAME=$(echo "${HP_TENANT%%.*}")
  logMessage "Helix Platform ${HP_COMPANY_NAME_LABEL} is ${HP_COMPANY_NAME}."
}

selectFromArray () {
  ARRAY="${1}[@]"
  select i in "${!ARRAY}"; do
    echo "${i}";
    break;
  done
}

deleteTCTLJob() {
  ${KUBECTL_BIN} -n "${HP_NAMESPACE}" delete job "${SEALTCTL}" --wait=true > /dev/null 2>&1
}

getTCTLOutput() {
  TCTL_OUTPUT=""
  if [ $(${KUBECTL_BIN} -n "${HP_NAMESPACE}" logs job/${SEALTCTL} | grep "^HTTP" | cut -f 4 -d ' ') != "200" ] ; then
    logError "115" "tctl job failed." 1
  fi
  if [ "${1}" != "full" ]; then
    TCTL_OUTPUT=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" logs job/${SEALTCTL} | sed -n -e '/^NAME/,$p' | tail -n +2)
  else
    TCTL_OUTPUT=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" logs job/${SEALTCTL})
  fi
}

setTCTLRESTImageName() {
  TCTL_JOB_NAME=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get job --no-headers -o custom-columns=':.metadata.name' | grep tctl$ | head -1)
  if [ ! -z "${TCTL_JOB_NAME}" ]; then
    return 0
  else
    return 1
  fi
}

deployTCTL() {
  TCTL_COMMAND="${1}"
  if ! setTCTLRESTImageName ; then
    logError "202" "Unable to find job with TCTL image details."
    return 1
  fi
  TCTL_IMAGE=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get job "${TCTL_JOB_NAME}" -o jsonpath='{.spec.template.spec.containers[0].image}')
  if [ -z "${TCTL_IMAGE}" ]; then
    logError "203" "Unable to get TCTL image name from job ${TCTL_JOB_NAME}."
    return 1
  fi
  logMessage "Deploying '${SEALTCTL}' job and waiting for it to complete..."
  cat <<EOF | ${KUBECTL_BIN} -n "${HP_NAMESPACE}" apply -f - >/dev/null
---
apiVersion: batch/v1
kind: Job
metadata:
  labels:
    app: ${SEALTCTL}
  name: ${SEALTCTL}
  namespace: ${HP_NAMESPACE}
spec:
  backoffLimit: 1
  completions: 1
  parallelism: 1
  template:
    metadata:
      labels:
        app: ${SEALTCTL}
    spec:
      containers:
      - env:
        - name: SERVICE_PORT
          value: "8000"
        - name: APP_URL
          value: http://tms:8000
        - name: CLIENT_ID
          value: "123"
        - name: CLIENT_SECRET
          value: "123"
        - name: RSSO_URL
          valueFrom:
            configMapKeyRef:
              key: rssourl
              name: rsso-admin-tas
        - name: COMMAND
          value: ${TCTL_COMMAND}
        image: ${TCTL_IMAGE}
        imagePullPolicy: IfNotPresent
        name: ${SEALTCTL}
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          runAsNonRoot: true
          seccompProfile:
            type: RuntimeDefault
        resources:
          limits:
            cpu: 512m
            memory: 512Mi
          requests:
            cpu: 256m
            memory: 256Mi
      restartPolicy: Never
      imagePullSecrets:
        - name: bmc-dtrhub
EOF

  # Wait for job to complete
  if ! ${KUBECTL_BIN} -n "${HP_NAMESPACE}" wait --for=condition=complete job/"${SEALTCTL}" --timeout=90s > /dev/null 2>&1; then
    logError "204" "Timed out waiting for job ${SEALTCTL} to complete."
    return 1
  else
    return 0
  fi
}

getRealmDetails() {
  REALM_NAME="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
  RSSO_REALM=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}")
  if echo "${RSSO_REALM}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    echo "Realms found in RSSO are:"
    ${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms -H "Authorization: RSSO ${RSSO_TOKEN}" | ${JQ_BIN}
    logError "116" "Realm ${REALM_NAME} not found for SAAS_TENANT in RSSO.  Check IS_CUSTOMER_SERVICE and IS_ENVIRONMENT values." 1
  else
    logMessage "RSSO realm ${REALM_NAME} found for the SAAS_TENANT."
  fi
}

checkTenantRealms() {
  TENANT_REALM=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}" -H "X-RSSO-TENANT-IMP: ${PORTAL_HOSTNAME}")
  if ! echo "${TENANT_REALM}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    logError "117" "Helix IS realm '${REALM_NAME}' exists for tenant '${HP_TENANT}' when it should be configured for the SAAS_TENANT."
#  else
#    logMessage "Verified Helix IS realm (${REALM_NAME}) is not configured for tenant ${HP_TENANT}."
  fi
}

validateRealm() {
  logMessage "Using realm - ${REALM_NAME}"
  # Parse realm data
  REALM_ARHOST=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arHost)
  if [ "${REALM_ARHOST}" != "platform-user-ext.${IS_NAMESPACE}" ]; then
    logError "118" "Invalid arHost value in realm - expected platform-user-ext.${IS_NAMESPACE} but found ${REALM_ARHOST}."
  else
    logMessage "AR host ${REALM_ARHOST} is the expected value."
  fi
  REALM_ARPORT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arPort)
  if [ "${REALM_ARPORT}" != "46262" ]; then
    logError "119" "Invalid arPort in realm - expected 46262 but found ${REALM_ARPORT}."
  else
    logMessage "AR port ${REALM_ARPORT} is the expected value."
  fi
  REALM_TENANT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .tenantDomain)
  if [ "${REALM_TENANT}" != "${HP_TENANT}" ]; then
    logWarning "004" "Unexpected TENANT in realm - recommended value is ${HP_TENANT} but found ${REALM_TENANT}."
  else
    logMessage "Tenant ${REALM_TENANT} is the expected value."
  fi
  REALM_DOMAINS=($(echo "${RSSO_REALM}" | ${JQ_BIN} -r '.domainMapping.domain[]' | tr "\n" " "))
  BAD_DOMAINS=0
  validateRealmDomains
  if [ "${BAD_DOMAINS}" == "1" ]; then
    logMessage "Application Domains found in SSO Realm ${REALM_NAME} are:"
    printf '  %s\n' "${REALM_DOMAINS[@]}"
  fi
}

validateRealmDomains() {
  logMessage "Checking for expected hostname aliases in realm Application Domains & DNS..."
  # Special case when IS_ENVIRONMENT is "prod"
  if [ "${IS_ENVIRONMENT}" == "prod" ]; then
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}"
    logMessage "ENVIRONMENT value is 'prod' - IS hostnames prefix is \"${IS_ALIAS_PREFIX}-\""
  else
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
    logMessage "IS hostnames prefix is \"${IS_ALIAS_PREFIX}\""
  fi
  # Check for midtier alias
  if ! echo "${REALM_DOMAINS[@]}" | grep -q "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN}" ; then
    logError "120" "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN} not found in the realm Application Domains list."
    BAD_DOMAINS=1
  else
    logMessage "  - ${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN} found in the realm Application Domains list."
  fi
  validateDomainInDNS "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN}"
  # Check for other IS aliases
  for i in "${IS_ALIAS_SUFFIXES[@]}"; do
    TARGET="${IS_ALIAS_PREFIX}-${i}.${CLUSTER_DOMAIN}"
    if ! echo "${REALM_DOMAINS[@]}" | grep -q "${TARGET}" ; then
      logError "120" "${TARGET} not found in Application Domains list."
      BAD_DOMAINS=1
    else
      logMessage "  - ${TARGET} found in realm Application Domains list."
    fi
    validateDomainInDNS "${TARGET}"
  done
  # Check for portal alias - will not be present if INTEROPS pipeline has not been run
  if ! echo "${REALM_DOMAINS[@]}" | grep -q "${PORTAL_HOSTNAME}" ; then
    logWarning "005" "${PORTAL_HOSTNAME} not found in the realm Application Domains list. This is expected until the HELIX_ITSM_INTEROPS pipeline has completed."
  fi
}

validateDomainInDNS() {
  # hostname to check
  if ! ${HOST_BIN} ${1} > /dev/null 2>>${HITT_DBG_FILE}; then
    logError "122" "Entry for ${1} not found in DNS."
  else
    logMessage "  - ${1} found in DNS."
  fi
}

checkServiceDetails() {
  deleteTCTLJob
  if ! deployTCTL "get service"; then
    logError "123" "Failed to get Helix Platform ARSERVICES status."
    return
  fi
  getTCTLOutput
  if ! echo "${TCTL_OUTPUT}" | grep -q "^ITSM "  ; then
    logError "124" "ITSM services not found in Helix Platform - please check that ARSERVICES=yes was set in your deployment.config file."
  else
    logMessage "ITSM services found in Helix Platform."
  fi
  if ! echo "${TCTL_OUTPUT}" | grep -q "^ITSMInsight"  ; then
    logMessage "ITSM Insights services are not installed."
    ITSM_INSIGHTS=1
  else
    logMessage "ITSM Insights services found in Helix Platform."
    ITSM_INSIGHTS=0
  fi
  deleteTCTLJob
}

checkFTSElasticStatus() {
  FTS_ELASTIC_STATUS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" ${FTS_ELASTIC_POD_CONTAINER} -- sh -c "curl -sk -u \"${LOG_ELASTICSEARCH_USERNAME}:${LOG_ELASTICSEARCH_PASSWORD}\" -X GET https://localhost:9200/_cluster/health?pretty | grep status")
  if ! echo "${FTS_ELASTIC_STATUS}" | grep -q green ; then
    logError "125" "FTS Elasticsearch problem. Check the ${FTS_ELASTIC_SERVICENAME} pods in Helix Platform namespace."
  else
    logMessage "FTS Elasticsearch (${FTS_ELASTIC_SERVICENAME}) appears healthy."
  fi
}

getISDetailsFromK8s() {
  [[ "${MODE}" != "post-is" ]] && return
  logMessage "Getting data from IS namespace..."
  IS_PLATFORM_STS=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.containers[?(@.name=="platform")]}')
  IS_PLATFORM_SECRET=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret platform-fts -o jsonpath='{.data}')

  IS_TENANT_DOMAIN=$(getValueFromPlatformSTS "TENANT_ID")
  IS_RSSO_URL=$(getValueFromPlatformSTS "RSSO_EXTERNAL_URL")
  IS_FTS_ELASTICSEARCH_HOSTNAME=$(getValueFromPlatformSTS "FTS_ELASTIC_HOST")
  IS_FTS_ELASTICSEARCH_PORT=$(getValueFromPlatformSTS "FTS_ELASTIC_SEARCH_PORT")
  IS_FTS_ELASTICSEARCH_SECURE=$(getValueFromPlatformSTS "FTS_ELASTIC_SEARCH_SECURE")
  IS_DB_TYPE=$(getValueFromPlatformSTS "AR_SERVER_DB_TYPE")
  IS_DB_PORT=$(getValueFromPlatformSTS "AR_SERVER_DB_PORT")
  IS_DATABASE_HOST_NAME=$(getValueFromPlatformSTS "AR_DB_SERVER_NAME")
  IS_AR_SERVER_APP_SERVICE_PASSWORD=$(getValueFromPlatformSTS "AR_SERVER_APP_SERVICE_PASSWORD")
  IS_AR_SERVER_DSO_USER_PASSWORD=$(getValueFromPlatformSTS "AR_SERVER_DSO_USER_PASSWORD")
  IS_AR_SERVER_MIDTIER_SERVICE_PASSWORD=$(getValueFromPlatformSTS "AR_SERVER_MIDTIER_SERVICE_PASSWORD")

  IS_AR_DB_NAME=$(getValueFromPlatformSecret "AR_DB_NAME")
  IS_AR_DB_PASSWORD=$(getValueFromPlatformSecret "AR_SERVER_DB_USER_PASSWORD")
  IS_AR_DB_USER=$(getValueFromPlatformSecret "AR_SERVER_DB_USERNAME")
  IS_ORACLE_SERVICE_NAME=$(getValueFromPlatformSecret "AR_DB_INSTANCE")

  # 23.3.03+ update for new FTS ES creds
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret helix-es-secret > /dev/null 2>&1; then
    ES_SECRET_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret helix-es-secret -o jsonpath='{.data}')
    IS_FTS_ELASTICSEARCH_USERNAME=$(echo "${ES_SECRET_JSON}" | ${JQ_BIN} '.ELASTIC_SEARCH_INDEX_USERNAME |@base64d')
    IS_FTS_ELASTICSEARCH_USER_PASSWORD=$(echo "${ES_SECRET_JSON}" | ${JQ_BIN} '.ELASTIC_SEARCH_INDEX_USER_PASSWORD |@base64d')
  else
    IS_FTS_ELASTICSEARCH_USERNAME=$(getValueFromPlatformSecret "FTS_ELASTIC_SEARCH_USERNAME")
    IS_FTS_ELASTICSEARCH_USER_PASSWORD=$(getValueFromPlatformSecret "FTS_ELASTIC_SEARCH_USER_PASSWORD")
  fi

  IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_PLATFORM_SECRET}" | ${JQ_BIN} -r '.CACERTS_SSL_TRUSTSTORE_PASSWORD')
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" != "null" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" | ${BASE64_BIN} -d)
  else
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi

  IS_ENABLE_PLATFORM_INT_NORMALIZATION="false"
  IS_PLATFORM_INT=0
  if [ $(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get pod -l app=platform-int 2>/dev/null | wc -l) != "0" ]; then
    IS_PLATFORM_INT=1
    if ${KUBECTL_BIN} -n ${IS_NAMESPACE} get sts platform-int -o jsonpath='{.spec.template.spec.containers[?(@.name=="platform")].env[?(@.name=="ENABLE_AR_SERVICES")].value}' | grep -q normalization; then
      IS_ENABLE_PLATFORM_INT_NORMALIZATION="true"
    fi
  fi

  IS_IMAGESECRET_NAME=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.imagePullSecrets[0].name}')

  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.containers[?(@.name=="fluent-bit")].name}' | grep -q fluent-bit; then
    IS_SIDECAR_FLUENTBIT=1
  else
    IS_SIDECAR_FLUENTBIT=0
  fi
}

getValueFromPlatformSTS() {
  echo "${IS_PLATFORM_STS}" | ${JQ_BIN} -r '. | select(.name=="platform") | .env[] | select(.name=="'"${1}"'") | .value'
}

getValueFromPlatformSecret() {
  echo "${IS_PLATFORM_SECRET}" | ${JQ_BIN} -r '."'"${1}"'" | @base64d'
}

checkJenkinsIsRunning() {
  if ! "${CURL_BIN}" -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/whoAmI/api/json?tree=authenticated" | grep -q WhoAmI ; then
    logError "126" "Jenkins not found on ${JENKINS_PROTOCOL}://${JENKINS_HOSTNAME}:${JENKINS_PORT} - skipping Jenkins tests."
    systemctl status jenkins > jenkins-status.log 2>&1
    SKIP_JENKINS=1
  else
    JENKINS_RESPONSE=$(${CURL_BIN} -skI "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}")
    JENKINS_VERSION=$(echo "${JENKINS_RESPONSE}" | grep -i 'X-Jenkins:' | awk '{print $2}' | tr -d '\r')
    JENKINS_HTTP_CODE=$(echo "${JENKINS_RESPONSE}" | grep "^HTTP" | cut -f 2 -d ' '| tr -d '\r')
    logMessage "Jenkins version ${JENKINS_VERSION} found on ${JENKINS_PROTOCOL}://${JENKINS_HOSTNAME}:${JENKINS_PORT}"
    if [ "${JENKINS_HTTP_CODE}" != "200" ]; then
      logError "127" "Jenkins authentication is enabled but the credentials in hitt.conf are blank or wrong.  Please set correct credentials in the HITT config file (${HITT_CONFIG_FILE})." 1
      SKIP_JENKINS=1
    fi
    getJenkinsCrumb
fi
}

getLastBuildFromJenkins() {
  # PIPELINE_NAME
  BUILD_NUMBER=$(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/job/${1}/lastBuild/buildNumber")
  echo "${BUILD_NUMBER}"
}

savePipelineConsoleOutput() {
  # PIPELINE_NAME / BUILD_NUMBER
  ${CURL_BIN} -skf "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/job/${1}/${2}/consoleText" > "${1}.log"
}

saveAllPipelineConsoleOutput() {
  createPipelineNamesArray
  for i in "${PIPELINE_NAMES[@]}"; do
    savePipelineConsoleOutput "${i}" "lastBuild"
  done
}

getISDetailsFromJenkins() {
  if [ "${MODE}" != "pre-is" ] || [ "${SKIP_JENKINS}" == "1" ]; then
    return
  fi
  #logMessage "Downloading jenkins-cli.jar from Jenkins..."
  #downloadJenkinsCLIJar
  #checkJenkinsCLIJavaVersion
  logMessage "Reading values from Jenkins..."
  JENKINS_JSON=$(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/job/HELIX_ONPREM_DEPLOYMENT/lastBuild/api/json")
  checkJenkinsJobResult
  JENKINS_ONPREM_DEPLOYMENT_LASTBUILD=$(getLastBuildFromJenkins HELIX_ONPREM_DEPLOYMENT)
  JENKINS_GENERATE_CONFIG_LASTBUILD=$(getLastBuildFromJenkins HELIX_GENERATE_CONFIG)
  logMessage "Last pipeline build numbers are - HELIX_ONPREM_DEPLOYMENT/${JENKINS_ONPREM_DEPLOYMENT_LASTBUILD} and HELIX_GENERATE_CONFIG/${JENKINS_GENERATE_CONFIG_LASTBUILD}."
  JENKINS_PARAMS=$(echo "${JENKINS_JSON}" | ${JQ_BIN} -r '.actions[] | select(._class=="hudson.model.ParametersAction") .parameters[]')
  getPipelineValues
}

checkJenkinsJobResult() {
  if ! echo "${JENKINS_JSON}" | ${JQ_BIN} -r .result | grep -q "SUCCESS"; then
    logWarning "006" "Last build of the HELIX_ONPREM_DEPLOYMENT pipeline was not successful. Please review the console output for this and the HELIX_GENERATE_CONFIG pipelines - saved in the HITT directory."
  fi
}

parseJenkinsParam() {
  echo "${JENKINS_PARAMS}" | ${JQ_BIN} -r ' . | select(.name=="'"$1"'") .value'
}

createPipelineVarsArray() {
  PIPELINE_VARS=(
    CHECKOUT_USING_USER
    CUSTOM_BINARY_PATH
    IS_CLOUD
    ROUTE_ENABLED
    ROUTE_TLS_ENABLED
    CLUSTER
    IS_NAMESPACE
#    CUSTOMER_NAME - removed as may have spaces
    INGRESS_CLASS
    CLUSTER_DOMAIN
    INPUT_CONFIG_METHOD
    DEPLOYMENT_MODE
    CUSTOMER_SIZE
    HELM_NODE
    SOURCE_VERSION
    PLATFORM_HELM_VERSION
    HELIX_ITSM_INSIGHTS
    HELIX_BWF
    HELIX_DWP
    HELIX_DWPA
    HELIX_MCSM
    HELIX_CLOUD_ACTIONS
    HELIX_SMARTAPPS_CSM
    HELIX_SMARTAPPS_FAS
    SIDECAR_SUPPORT_ASSISTANT_FPACK
    SUPPORT_ASSISTANT_CREATE_ROLE
    SUPPORT_ASSISTANT_TOOL
    SIDECAR_FLUENTBIT
    REGISTRY_TYPE
    HARBOR_REGISTRY_HOST
    IMAGE_REGISTRY_USERNAME
    IMAGESECRET_NAME
    DB_TYPE
    DB_SSL_ENABLED
    DB_PORT
    DATABASE_RESTORE
    DATABASE_HOST_NAME
    DATABASE_ADMIN_USER
    ORACLE_SERVICE_NAME
    DATABASE_RESTORE
    IS_DATABASE_ALWAYS_ON
    LOGS_ELASTICSEARCH_HOSTNAME
    LOGS_ELASTICSEARCH_TLS
    AR_DB_NAME
    AR_DB_USER
    AR_DB_CASE_SENSITIVE
    FTS_ELASTICSEARCH_HOSTNAME
    FTS_ELASTICSEARCH_PORT
    FTS_ELASTICSEARCH_SECURE
    SMARTREPORTING_DB_NAME
    SMARTREPORTING_DB_USER
    PLATFORM_SR_DB_JDBC_URL
    PLATFORM_SR_DB_USER
    VC_RKM_USER_NAME
    VC_PROXY_USER_LOGIN_NAME
    DWP_CONFIG_PRIMARY_ORG_NAME
    PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS
    ENABLE_PLATFORM_INT_NORMALIZATION
    RSSO_URL
    RSSO_ADMIN_USER
    TENANT_DOMAIN
    HELIX_PLATFORM_NAMESPACE
    HELIX_PLATFORM_CUSTOMER_NAME
    BMC_HELIX_ITSM_INSIGHTS
    BMC_HELIX_SMART_IT
    BMC_HELIX_BWF
    BMC_HELIX_DWP
    BMC_HELIX_INNOVATION_STUDIO
    BMC_HELIX_DWPA
  )
}

createInputFileVarsArray() {
  INPUT_FILE_VARS=(
    AR_DB_PASSWORD
    AR_SERVER_APP_SERVICE_PASSWORD
    AR_SERVER_DSO_USER_PASSWORD
    AR_SERVER_MIDTIER_SERVICE_PASSWORD
    BAKEDUSER_HANNAH_ADMIN_PASSWORD
    DB_ADMIN_PASSWORD
    SMARTREPORTING_DB_PASSWORD
    PLATFORM_SR_DB_PASSWORD
    RSSO_ADMIN_PASSWORD
    PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USER_PASSWORD
    PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USERNAME
    PLATFORM_COMMON_CACERTS_SSL_TRUSTSTORE_PASSWORD
    SIDECAR_FLUENT_PASSWORD
  )
}

downloadJenkinsCLIJar() {
  ${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/jnlpJars/jenkins-cli.jar" -o jenkins-cli.jar
}

getPipelinePasswords() {
  SCRIPT='import jenkins.model.*
    import hudson.model.*
    def jobName = "HELIX_ONPREM_DEPLOYMENT"
    def jenkins = Jenkins.instance
    def job = jenkins.getItemByFullName(jobName)
    def lastBuild = job.getLastBuild()
    def parametersAction = lastBuild.getAction(ParametersAction)
    def parameters = lastBuild.getAction(ParametersAction.class)?.getParameters()
    def paramMap = [:]
    if (parameters != null) {
        parameters.each { param ->
            if (param.getName() ==~ ".*PASSWORD.*") {
              paramMap[param.getName()] = param.getValue()
            }
        }
    }
    def jsonOutput = new groovy.json.JsonBuilder(paramMap).toPrettyString()
    println(jsonOutput)'

  runJenkinsCurl "${SCRIPT}"
}

getPipelineValues() {
  createPipelineVarsArray
  for i in "${PIPELINE_VARS[@]}"; do
    eval "IS_$i=$(parseJenkinsParam ${i})"
  done
  ISP_CUSTOMER_SERVICE=$(parseJenkinsParam CUSTOMER_SERVICE)
  ISP_ENVIRONMENT=$(parseJenkinsParam ENVIRONMENT)
  if isBlank "${ISP_CUSTOMER_SERVICE}" || isBlank "${ISP_ENVIRONMENT}" ; then
    logError "128" "CUSTOMER_SERVICE and/or ENVIRONMENT are blank - please enter all required values in the HELIX_ONPREM_DEPLOYMENT pipeline." 1
  fi
  if [ "${IS_CUSTOMER_SIZE}" == "M" ] || [ "${IS_CUSTOMER_SIZE}" == "L" ] || [ "${IS_CUSTOMER_SIZE}" == "XL" ]; then
    IS_PLATFORM_INT=1
  fi
  IS_IMAGE_REGISTRY_PASSWORD=$(getPipelinePasswords | ${JQ_BIN} -r '.IMAGE_REGISTRY_PASSWORD.plainText')
  IS_PIPELINE_VERSION="${IS_PLATFORM_HELM_VERSION:2:2}.${IS_PLATFORM_HELM_VERSION:4:1}.${IS_PLATFORM_HELM_VERSION:5:2}"
  IS_VERSION="${IS_PLATFORM_HELM_VERSION:0:7}"
  cloneCustomerConfigsRepo
}

checkPipelinePwds() {
  if [ "${MODE}" != "pre-is" ]; then return; fi
  PASSWDS_JSON=$(getPipelinePasswords | ${JQ_BIN} 'to_entries')
  for i in $(echo "${PASSWDS_JSON}" | ${JQ_BIN} -r '.[].key'); do
    PASSWD=$(echo "${PASSWDS_JSON}" | ${JQ_BIN} -r ".[] | select(.key==\"${i}\").value.plainText")
    if echo "${PASSWD}" | grep -q '\$' ; then
      logError "191" "The value of the pipeline parameter '${i}' contains a '$' character which will cause errors."
    fi
done
}

getInputFileValues() {
  # Replace ' with " in input file to allow parsing
  sed -i 's/'\''/"/g' "${INPUT_CONFIG_FILE}"
  createInputFileVarsArray
  for i in "${INPUT_FILE_VARS[@]}"; do
    eval "IS_$i=$(grepInputFile $i)"
  done
  IS_FTS_ELASTICSEARCH_USER_PASSWORD="${IS_PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USER_PASSWORD}"
  IS_FTS_ELASTICSEARCH_USERNAME="${IS_PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USERNAME}"
  IS_CACERTS_SSL_TRUSTSTORE_PASSWORD="${IS_PLATFORM_COMMON_CACERTS_SSL_TRUSTSTORE_PASSWORD}"
  IS_LOGS_ELASTICSEARCH_PASSWORD="${IS_SIDECAR_FLUENT_PASSWORD}"

  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi
}

grepInputFile() {
  grep "^${1}" "${INPUT_CONFIG_FILE}"  | awk -F '"' '{print $2}'
}

cloneCustomerConfigsRepo() {
  SKIP_REPO=0
  export GIT_SSH_COMMAND="ssh -oBatchMode=yes"
  GIT_REPO_DIR=$(parseJenkinsParam GIT_REPO_DIR)
  INPUT_CONFIG_FILE="configsrepo/customer/${IS_CUSTOMER_SERVICE}/${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}.sh"
  if ! ${GIT_BIN} clone "${GIT_REPO_DIR}"/CUSTOMER_CONFIGS/onprem-remedyserver-config.git configsrepo > /dev/null 2>&1 ; then
    logError "129" "Failed to clone ${GIT_REPO_DIR}/CUSTOMER_CONFIGS/onprem-remedyserver-config.git"
    SKIP_REPO=1
    return
  else
    logMessage "Cloned CUSTOMER_CONFIGS repo to configsrepo directory."
  fi
  if [ ! -f "${INPUT_CONFIG_FILE}" ]; then
    logError "130" "Input configuration file (${INPUT_CONFIG_FILE}) not found. Has the HELIX_GENERATE_CONFIG pipeline been run successfully?"
    SKIP_REPO=1
    return
  else
    logMessage "Input config file found - ${INPUT_CONFIG_FILE}."
    getInputFileValues
  fi
}

isBlank() {
  [[ -z "${1}" ]] && return 0 || return 1
}

checkBlank() {
  if isBlank "${!1}"; then
    logError "131" "Value for ${1:3} is not expected to be blank."
  else
    logMessage "Value set for ${1:3}."
  fi
}

validateISDetails() {
  [[ "${SKIP_JENKINS}" == "1" ]] && return
  # Common to pre and post
  if [ "${IS_TENANT_DOMAIN}" != "${REALM_TENANT}" ]; then
    logError "132" "TENANT_DOMAIN (${IS_TENANT_DOMAIN}) does not match the Helix Platform realm Tenant (${REALM_TENANT})."
  else
    logMessage "TENANT_DOMAIN matches the realm Tenant (${REALM_TENANT})."
  fi

  if [ "${IS_RSSO_URL}" != "${RSSO_URL}" ]; then
    logError "133" "The RSSO_URL value in the HELIX_ONPREM_DEPLOYMENT pipeline (${IS_RSSO_URL}) does not match the Helix Platform RSSO_URL (${RSSO_URL})."
  else
    logMessage "IS RSSO_URL is the expected value of ${RSSO_URL}."
  fi

  if [ "${#IS_AR_SERVER_APP_SERVICE_PASSWORD}" -gt 19 ]; then
    logError "134" "AR_SERVER_APP_SERVICE_PASSWORD is too long - maximum of 19 characters."
  else
    logMessage "AR_SERVER_APP_SERVICE_PASSWORD length is 19 characters or less."
  fi

  if [ "${#IS_AR_SERVER_DSO_USER_PASSWORD}" -gt 20 ]; then
    logError "135" "AR_SERVER_DSO_USER_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_DSO_USER_PASSWORD length is 20 characters or less."
  fi

  if [ "${#IS_AR_SERVER_MIDTIER_SERVICE_PASSWORD}" -gt 20 ]; then
    logError "135" "AR_SERVER_MIDTIER_SERVICE_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_MIDTIER_SERVICE_PASSWORD length is 20 characters or less."
  fi

  if [ "${IS_PLATFORM_INT}" == "1" ] ; then
    if [ "${IS_ENABLE_PLATFORM_INT_NORMALIZATION}" == "false" ] && [ "${IS_VERSION}" -lt 2023303 ]; then
      logWarning "007" "platform-int pods are enabled but ENABLE_PLATFORM_INT_NORMALIZATION is not selected."
    fi
    if [ "${IS_ENABLE_PLATFORM_INT_NORMALIZATION}" == "true" ] && [ "${IS_VERSION}" -ge 2023303 ]; then
      logWarning "033" "ENABLE_PLATFORM_INT_NORMALIZATION is selected but will be ignored."
    fi
  fi

  # PRE mode only
  if [ "${MODE}" == "pre-is" ]; then
    logMessage "ITSM pipeline version is ${IS_PLATFORM_HELM_VERSION}."
    logMessage "CUSTOMER_SIZE is ${IS_CUSTOMER_SIZE}."
    logMessage "DEPLOYMENT_MODE is ${IS_DEPLOYMENT_MODE}."

    if [ "${IS_CHECKOUT_USING_USER}" == "" ]; then
      logError "" "CHECKOUT_USING_USER is blank but should be the Jenkins credentials ID used to access the git repository files.  Default is 'github'."
    fi

    if [ "${IS_DEPLOYMENT_MODE}" == "UPGRADE" ] || [ "${IS_DEPLOYMENT_MODE}" == "UPDATE" ]; then
      CURRENT_VER=$(echo "${IS_SOURCE_VERSION}" | tr -d .)
      TARGET_VER=$(echo "${IS_PLATFORM_HELM_VERSION}" | tr -d .)
      if [ "${CURRENT_VER}" -ge "${TARGET_VER}" ]; then
        logError "213" "SOURCE_VERSION is greater than or equal to the PLATFORM_HELM_VERSION but the DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}'."
      fi
      if [ "${CURRENT_VER:0:5}" -eq "${TARGET_VER:0:5}" ] && [ "${IS_DEPLOYMENT_MODE}" != "UPDATE" ]; then
        logError "213" "DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}' but should be 'UPDATE' as the source and target have the same major versions."
      fi
      if [ "${CURRENT_VER:0:5}" -ne "${TARGET_VER:0:5}" ] && [ "${IS_DEPLOYMENT_MODE}" != "UPGRADE" ]; then
        logError "213" "DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}' but should be 'UPGRADE' as the source and target have different major versions."
      fi
    fi

    if [ "${IS_CUSTOM_BINARY_PATH}" == "true" ]; then
      logWarning "008" "CUSTOM_BINARY_PATH option is selected - this is not usually required and may be a mistake."
    fi

    if ! ${KUBECTL_BIN} config get-contexts "${IS_CLUSTER}" > /dev/null 2>&1; then
      logError "137" "CLUSTER (${IS_CLUSTER}) is not a valid context in your kubeconfig file. Available contexts are:"
      ${KUBECTL_BIN} config get-contexts
    else
      logMessage "CLUSTER (${IS_CLUSTER}) is a valid kubeconfig context."
    fi

    if [ "${IS_CLOUD}" == "true" ]; then
      logWarning "009" "IS_CLOUD option is selected - this will cause public cloud systems to provision an external load balancer."
    fi

    if [ "${IS_ROUTE_ENABLED}" == "true" ] || [ "${IS_ROUTE_TLS_ENABLED}" == "true" ]; then
      logWarning "010" "ROUTE_ENABLED and/or ROUTE_TLS_ENABLED are selected but should not be."
    fi

    if [ "${IS_IS_NAMESPACE}" != "${IS_NAMESPACE}" ]; then
      logError "138" "The IS_NAMESPACE value (${IS_IS_NAMESPACE}) does not match the IS_NAMESPACE defined in the hitt.conf file (${IS_NAMESPACE})."
    else
      logMessage "IS_NAMESPACE is the expected value (${IS_NAMESPACE})."
    fi

    if [ "${IS_VERSION}" -ge 2023303 ]; then
      IS_NS_MAX_LEN=23
    else
      IS_NS_MAX_LEN=33
    fi
    if [ "${#IS_IS_NAMESPACE}" -gt ${IS_NS_MAX_LEN} ]; then
      logError "139" "IS_NAMESPACE name is too long - maximum of ${IS_NS_MAX_LEN} characters."
    else
      logMessage "IS_NAMESPACE name length is ${IS_NS_MAX_LEN} characters or less."
    fi

    if [ "${ISP_CUSTOMER_SERVICE}-${ISP_ENVIRONMENT}" != "${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}" ]; then
      logError "140" "CUSTOMER_SERVICE (${ISP_CUSTOMER_SERVICE}) and/or ENVIRONMENT (${ISP_ENVIRONMENT}) values do not match those set in the hitt.conf file - (${IS_CUSTOMER_SERVICE} and ${IS_ENVIRONMENT})."
    else
      logMessage "CUSTOMER_SERVICE and ENVIRONMENT appear valid (${ISP_CUSTOMER_SERVICE} / ${ISP_ENVIRONMENT})."
    fi

    if checkK8sAuth get ingressclasses; then
      if isBlank "${IS_INGRESS_CLASS}" || ! ${KUBECTL_BIN} get ingressclasses "${IS_INGRESS_CLASS}" > /dev/null 2>&1 ; then
        logError "141" "INGRESS_CLASS (${IS_INGRESS_CLASS})is blank or not valid."
      else
        logMessage "INGRESS_CLASS (${IS_INGRESS_CLASS}) appears valid."
      fi
    else
      logWarning "011" "Unable to list ingressclasses - skipping INGRESS_CLASS checks."
    fi

    if [ "${IS_CLUSTER_DOMAIN}" != "${CLUSTER_DOMAIN}" ]; then
      logError "142" "CLUSTER_DOMAIN (${IS_CLUSTER_DOMAIN}) does not match that used for the Helix Platform (${CLUSTER_DOMAIN})."
    else
      logMessage "CLUSTER_DOMAIN has the expected value of ${CLUSTER_DOMAIN}."
    fi

    if [ "${IS_INPUT_CONFIG_METHOD}" != "Generate_Input_File" ]; then
      logError "143" "INPUT_CONFIG_METHOD should be Generate_Input_File."
    else
      logMessage "INPUT_CONFIG_METHOD has the expected value of Generate_Input_File."
    fi

    if isBlank "${IS_HELM_NODE}" ; then
      logError "144" "HELM_NODE is blank."
    else
      NODE_ARRAY=($(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/computer/api/json" | ${JQ_BIN} -r .computer[].displayName | grep -v Built ))
      NODE_MATCH=0
      for i in "${NODE_ARRAY[@]}"; do
        if [ "${IS_HELM_NODE}" == "${i}" ]; then NODE_MATCH=1; fi
      done
      if [ "${NODE_MATCH}" == 1"" ]; then
        logMessage "HELM_NODE (${IS_HELM_NODE}) is a valid node in Jenkins."
      else
        logError "145" "HELM_NODE (${IS_HELM_NODE}) not found as a Jenkins node.  Available nodes are:"
        printf '%s\n' "${NODE_ARRAY[@]}"
      fi
    fi

    if [ -n "${IS_HELIX_CLOUD_ACTIONS}" ]; then
      if [ "${IS_HELIX_CLOUD_ACTIONS}" == "true" ] && [ "${IS_HELIX_DWPA}" != "true" ]; then
        logError "104" "HELIX_CLOUD_ACTIONS is selected but this option requires HELIX_DWPA, which is not selected."
      fi
    fi

    if [ -n "${IS_HELIX_MCSM}" ]; then
      if [ "${IS_HELIX_MCSM}" == "true" ] && [ "${IS_HELIX_BWF}" != "true" ]; then
        logError "104" "HELIX_MCSM is selected but this option requires HELIX_BWF, which is not selected."
      fi
    fi

    if [ -n "${IS_HELIX_SMARTAPPS_CSM}" ]; then
      if [ "${IS_HELIX_SMARTAPPS_CSM}" == "true" ] && [ "${IS_HELIX_BWF}" != "true" ]; then
        logError "104" "HELIX_SMARTAPPS_CSM is selected but this option requires HELIX_BWF, which is not selected."
      fi
    fi

    if [ -n "${IS_HELIX_SMARTAPPS_FAS}" ]; then
      if [ "${IS_HELIX_SMARTAPPS_FAS}" == "true" ] && [ "${IS_HELIX_BWF}" != "true" ]; then
        logError "104" "HELIX_SMARTAPPS_FAS is selected but this option requires HELIX_BWF, which is not selected."
      fi
    fi

    if [ "${ITSM_INSIGHTS}" == "1" ]; then
      if  [ "${IS_HELIX_ITSM_INSIGHTS}" == "true" ] ; then
        logWarning "012" "HELIX_ITSM_INSIGHTS is selected but ITSM Insights is not installed in the Helix Platform."
      fi
      if [ "${IS_BMC_HELIX_ITSM_INSIGHTS}" == "true" ]; then
        logError "205" "BMC_HELIX_ITSM_INSIGHTS is selected but ITSM Insights is not installed in the Helix Platform."
      fi
    fi

    if [ "${IS_BMC_HELIX_ITSM_INSIGHTS}" == "true" ] && [ "${IS_HELIX_ITSM_INSIGHTS}" == "false" ] ; then
      logWarning "013" "BMC_HELIX_ITSM_INSIGHTS is selected in the INTEROPS section but HELIX_ITSM_INSIGHTS is not selected as a product to install."
    fi

#    if [ "${IS_SUPPORT_ASSISTANT_TOOL}" != "true" ]; then
#      logWarning "SUPPORT_ASSISTANT_TOOL not selected - Support Assistant Tool is recommended to provide access to application logs."
#    fi
    if [ "${IS_SIDECAR_SUPPORT_ASSISTANT_FPACK}" != "true" ]; then
      logWarning "014" "SIDECAR_SUPPORT_ASSISTANT_FPACK not selected - Support Assistant Tool will not be able to access application logs."
    fi
    if [ "${IS_SUPPORT_ASSISTANT_CREATE_ROLE}" != "true" ]; then
      logWarning "015" "SUPPORT_ASSISTANT_CREATE_ROLE not selected - Support Assistant Tool will not be able to access application logs unless the role/rolebinding are created manually."
    fi

    if [ "${IS_REGISTRY_TYPE}" != "DTR" ]; then
      logError "146" "REGISTRY_TYPE must be DTR."
    else
      logMessage "REGISTRY_TYPE is the expected value of DTR."
    fi

    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${HP_REGISTRY_SERVER}" ]; then
      logError "147" "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) does not match the Helix Platform registry server (${HP_REGISTRY_SERVER})."
    else
      logMessage "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) matches the Helix Platform registry server (${HP_REGISTRY_SERVER})."
    fi

    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${HP_REGISTRY_USERNAME}" ]; then
      logError "148" "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) does not match the Helix Platform registry username (${HP_REGISTRY_USERNAME})."
    else
      logMessage "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) matches the Helix Platform registry username (${HP_REGISTRY_USERNAME})."
    fi

    if [ "${IS_DB_SSL_ENABLED}" == "true" ]; then
        logError "149" "DB_SSL_ENABLED should not be selected."
    fi

    if [ "${IS_IS_DATABASE_ALWAYS_ON}" == "true" ]; then
      if [ "${IS_DB_TYPE}" != "mssql" ]; then
        logWarning "031" "IS_DATABASE_ALWAYS_ON is selected but this option is only valid for MSSQL databases and will be ignored."
      else
        logWarning "032" "IS_DATABASE_ALWAYS_ON is selected, please make sure you are using an MSSQL AlwaysOn database cluster and that the other DB details are set correctly."
      fi
    fi

    if [ -n "${IS_AR_DB_CASE_SENSITIVE}" ]; then
      if [ "${IS_DB_TYPE}" == "postgres" ] && [ "${IS_DATABASE_RESTORE}" == "true" ]; then
        if [ "${IS_AR_DB_CASE_SENSITIVE}" == "true" ]; then
          logMessage "Case sensitive database will be restored."
        else
          logMessage "Case insensitive database will be restored."
        fi
      fi
      if [ "${IS_AR_DB_CASE_SENSITIVE}" == "true" ]; then
        if ([ "${IS_DB_TYPE}" == "postgres" ] && [ "${IS_DATABASE_RESTORE}" == "false" ]) || ([ "${IS_DB_TYPE}" != "postgres" ]); then
          logWarning "024" "AR_DB_CASE_SENSITIVE is selected but will be ignored as it is only relevant when the database type is Postgres and the DATABASE_RESTORE option is selected."
        fi
      fi
    fi

    if [ "${#IS_SMARTREPORTING_DB_PASSWORD}" -gt 28 ]; then
      logError "212" "SMARTREPORTING_DB_PASSWORD is too long - maximum of 28 characters."
    fi

    if [ -n "${IS_AR_DB_CASE_SENSITIVE}" ] && [ "${IS_DB_TYPE}" == "postgres" ] && [ "${IS_AR_DB_CASE_SENSITIVE}" == "true" ]; then
      logMessage "Case sensitive database will be restored."
    fi

    if [ "$HELIX_LOGGING_DEPLOYED" == 0 ]; then
      if [ "${IS_SIDECAR_FLUENTBIT}" == true ]; then
        logWarning "016" "SIDECAR_FLUENTBIT selected but Helix Logging is not installed."
      fi
    fi

    if [ "$HELIX_LOGGING_DEPLOYED" == 1 ]; then
      if [ "${IS_LOGS_ELASTICSEARCH_TLS}" != "true" ]; then
        logError "151" "LOGS_ELASTICSEARCH_TLS (${IS_LOGS_ELASTICSEARCH_TLS}) is not the expected value of true."
      else
        logMessage "LOGS_ELASTICSEARCH_TLS is the expected value of true."
      fi
      if [ "${IS_LOGS_ELASTICSEARCH_PASSWORD}" != "${HELIX_LOGGING_PASSWORD}" ]; then
        logError "152" "LOGS_ELASTICSEARCH_PASSWORD does not match the Helix Platform KIBANA_PASSWORD."
      else
        logMessage "LOGS_ELASTICSEARCH_PASSWORD matches the Helix Platform KIBANA_PASSWORD."
      fi
      checkIsValidElastic "${IS_LOGS_ELASTICSEARCH_HOSTNAME}" "LOGS_ELASTICSEARCH_HOSTNAME"
    fi

    if [ "${IS_IMAGE_REGISTRY_PASSWORD}" != "${HP_REGISTRY_PASSWORD}" ]; then
      logError "153" "IMAGE_REGISTRY_PASSWORD does not match the Helix Platform registry password."
    else
      logMessage "IMAGE_REGISTRY_PASSWORD matches the Helix Platform registry password."
    fi

    if [ "$IS_VC_RKM_USER_NAME" == "${IS_VC_PROXY_USER_LOGIN_NAME}" ] || [ -z "$IS_VC_RKM_USER_NAME" ] || [ -z "${IS_VC_PROXY_USER_LOGIN_NAME}" ]; then
      logError "154" "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME must be different and cannot be blank."
    else
      logMessage "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME appear valid."
    fi

    if [ -n "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" ] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ ^\[.* ]] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ .*\]$ ]]; then
      logError "155" "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS (${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}) does not match the expected format of [x.x.x.x] - missing square brackets?"
    else
      logMessage "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS is blank or matches the expected format - (${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS})."
    fi

    if [ "${IS_RSSO_ADMIN_USER,,}" != "${RSSO_USERNAME,,}" ]; then
      logError "156" "RSSO_ADMIN_USER (${IS_RSSO_ADMIN_USER}) does not match the Helix Platform RSSO_ADMIN_USER (${RSSO_USERNAME})."
    else
      logMessage "RSSO_ADMIN_USER is the expected value of ${IS_RSSO_ADMIN_USER}."
    fi

    if [ "${IS_HELIX_PLATFORM_NAMESPACE}" != "${HP_NAMESPACE}" ]; then
      logError "157" "HELIX_PLATFORM_NAMESPACE (${IS_HELIX_PLATFORM_NAMESPACE}) is not the expected value of ${HP_NAMESPACE}."
    else
      logMessage "HELIX_PLATFORM_NAMESPACE is the expected value of ${HP_NAMESPACE}."
    fi

    if [ "${IS_HELIX_PLATFORM_CUSTOMER_NAME}" != "${HP_COMPANY_NAME}" ]; then
      logError "158" "HELIX_PLATFORM_CUSTOMER_NAME (${IS_HELIX_PLATFORM_CUSTOMER_NAME}) is not the expected value of ${HP_COMPANY_NAME}."
    else
      logMessage "HELIX_PLATFORM_CUSTOMER_NAME is the expected value of ${HP_COMPANY_NAME}."
    fi
  fi
}

getCacertsFile() {
  SKIP_CACERTS=0
  if [ "${MODE}" == "pre-is" ]; then
    if [ -f configsrepo/customer/customCerts/cacerts ] ; then
      cp -f configsrepo/customer/customCerts/cacerts sealcacerts
      logMessage "cacerts file found in CUSTOMER_CONFIGS repo."
      return
    else
      logWarning "017" "cacerts file not found - remember to attach when building the HELIX_ONPREM_DEPLOYMENT pipeline unless using a Digicert certificate."
      SKIP_CACERTS=1
    fi
  fi

  if [ "${MODE}" == "post-is" ]; then
    logMessage "Extracting cacerts file from Helix IS cacerts secret..."
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts > /dev/null 2>&1; then
      logError "159" "'cacerts' secret not found in Helix IS namespace."
      SKIP_CACERTS=1
      return
    fi
    IS_CACERTS_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts -o json)
    IS_CACERTS=$(echo "${IS_CACERTS_JSON}" | ${JQ_BIN} -r '.data.cacerts')
    if [ "${IS_CACERTS}" == "null" ]; then
      logError "160" "Required file 'cacerts' not found in the cacerts secret. File(s) in the secret are:"
      echo "${IS_CACERTS_JSON}" | ${JQ_BIN} '.data | keys'
      SKIP_CACERTS=1
    else
      echo "${IS_CACERTS}" | ${BASE64_BIN} -d > sealcacerts
    fi
  fi
}

validateCacerts() {
  getCacertsFile
  if [ "${SKIP_CACERTS}" == "1" ]; then
    logMessage "cacerts file not found - skipping checks."
    return
  fi
  CACERTS_FILETYPE=$(file sealcacerts | cut -f 2- -d ' ')
  if [ "${CACERTS_FILETYPE,,}" != "java keystore" ]; then
    logError "161" "cacerts file is of type '${CACERTS_FILETYPE}' and not the expected Java keystore."
    return
  else
    logMessage "cacerts file is a valid Java keystore."
  fi

  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" != "changeit" ]; then
    logMessage "CACERTS_SSL_TRUSTSTORE_PASSWORD is set - using non-default password for cacerts."
    if ! ${KEYTOOL_BIN} -list -keystore sealcacerts -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" > /dev/null 2>&1 ; then
      logError "214" "The value of CACERTS_SSL_TRUSTSTORE_PASSWORD is not set to the correct password for the cacerts file."
      return
    fi
  fi

  if ! ${KEYTOOL_BIN} -list -keystore sealcacerts -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -alias "${FTS_ELASTIC_CERTNAME}" > /dev/null 2>&1 ; then
    logError "162" "cacerts file does not contain the expected ${FTS_ELASTIC_CERTNAME} certificate required for FTS Elasticsearch connection."
  else
    logMessage "cacerts file contains the expected Elasticsearch ${FTS_ELASTIC_CERTNAME} certificate."
  fi

  # Convert JKS to pem
  logMessage "Processing cacerts..."
  unpackSSLPoke
  VALID_CACERTS=0
#  ${KEYTOOL_BIN} -importkeystore -srckeystore sealcacerts -destkeystore sealstore.p12 -srcstoretype jks -deststoretype pkcs12 -srcstorepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -deststorepass changeit > /dev/null 2>&1
#  ${OPENSSL_BIN} pkcs12 -in sealstore.p12 -out sealstore.pem -password pass:"${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" > /dev/null 2>&1
#  if ! ${CURL_BIN} -s "${RSSO_URL}" --cacert sealstore.pem > /dev/null 2>&1 ; then
  if ! ${JAVA_BIN} -Djavax.net.ssl.trustStore=sealcacerts "-Djavax.net.ssl.trustStorePassword=${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" SSLPoke "${LB_HOST}" 443 > /dev/null 2>&1 ; then
    logError "163" "cacerts file does not appear to contain the certificates required to connect to the Helix Platform LB_HOST."
    VALID_CACERTS=1
  fi
  for i in "${IS_ALIAS_SUFFIXES[@]}"; do
    TARGET="${IS_ALIAS_PREFIX}-${i}.${CLUSTER_DOMAIN}"
#    if ! ${CURL_BIN} -s "https://${TARGET}" --cacert sealstore.pem > /dev/null 2>&1; then
    if ! ${JAVA_BIN} -Djavax.net.ssl.trustStore=sealcacerts "-Djavax.net.ssl.trustStorePassword=${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" SSLPoke "${TARGET}" 443 > /dev/null 2>&1 ; then
      logError "164" "Certificate for ${TARGET} not found in cacerts."
      VALID_CACERTS=1
    else
      logMessage "  - valid certificate for ${TARGET} found in cacerts file."
    fi
  done

  if [ "${VALID_CACERTS}" == 0 ]; then
    logMessage "cacerts file appears valid."
  fi
}

checkISFTSElasticHost() {
  # IP/service.ns pipeline_param_name
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "165" "FTS_ELASTICSEARCH_HOSTNAME IP address (${1}) not found as an externalIP for any exposed service in the Helix Platform namespace."
    else
      logWarning "018" "Recommend using 'servicename.namespace' format instead of an exposed IP address for FTS_ELASTICSEARCH_HOSTNAME."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u "${LOG_ELASTICSEARCH_USERNAME}:${LOG_ELASTICSEARCH_PASSWORD}" -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "166" "${1} does not appear to be a valid Elasticsearch server IP address."
      else
        if ! echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name' | grep -q 'logs$' ; then
          logError "167" "${1} does not appear to be the expected Elasticsearch service instance for FTS."
          echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name'
        else
          logMessage "${1} appears to be a valid Elasticsearch service instance for FTS."
        fi
      fi
    fi
  else
    if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
      logError "168" "FTS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
    else
      logMessage "FTS_ELASTICSEARCH_HOSTNAME appears valid (${1})."
    fi
  fi
}

checkIsValidElastic() {
  BAD_ELASTIC=0
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "169" "${2} IP address (${1}) not found as an externalIP for any exposed service in the Helix Platform namespace."
      return
    else
      logWarning "019" "Recommend using 'servicename.namespace' format instead of an exposed IP address for ${2}."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u "${3}:${4}" -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "170" "${1} does not appear to be a valid Elasticsearch server IP address."
        return
      fi
    fi
  else
    case "${2}" in
      FTS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
          logError "168" "FTS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
        fi
        ;;
      LOGS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${EFK_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
          logError "172" "LOGS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${EFK_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
        fi
        ;;
    esac
  fi
}

getSvcFromExternalIP() {
  SERVICE_NAME=$(${KUBECTL_BIN} get svc -n "${HP_NAMESPACE}" -o jsonpath='{.items[?(@.spec.externalIPs[0]=="'"${1}"'")].metadata.name}')
  [[ -n $SERVICE_NAME ]] && echo 0 || echo 1
}

checkFTSElasticSettings() {
  BAD_FTS_ELASTIC=0
  if [ "${IS_FTS_ELASTICSEARCH_PORT}" != "9200" ]; then
    logError "173 ""FTS_ELASTICSEARCH_PORT (${IS_FTS_ELASTICSEARCH_PORT}) is not the expected value of 9200."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_PORT is the expected value of 9200."
  fi

  if [ "${IS_FTS_ELASTICSEARCH_SECURE}" != "true" ]; then
    logError "174" "FTS_ELASTICSEARCH_SECURE (${IS_FTS_ELASTICSEARCH_SECURE}) is not the expected value of 'true'."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_SECURE is the expected value of 'true'."
  fi

# Not expected as FTS user is not a pipeline var.
#  if [ "${IS_FTS_ELASTICSEARCH_USERNAME}" != "admin" ] || [ "${IS_FTS_ELASTICSEARCH_USERNAME}" != "bmcuser" ]; then
#    logError "Unexpected value for FTS_ELASTICSEARCH_USERNAME."
#    BAD_FTS_ELASTIC=1
#  fi

#  if [ "${IS_FTS_ELASTICSEARCH_USERNAME}" == "admin" ]; then
#    if  [ "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}" != "admin" ]; then
#      logError "FTS_ELASTICSEARCH_USER_PASSWORD is not the expected value when FTS_ELASTICSEARCH_USERNAME is 'admin'."
#      BAD_FTS_ELASTIC=1
#    fi
#  fi

  #if [ "${IS_FTS_ELASTICSEARCH_USERNAME}" == "bmcuser" ]; then
  if [ "${MODE}" == "pre-is" ] && [ "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}" != "${LOG_ELASTICSEARCH_PASSWORD}" ]; then
    logError "175" "FTS_ELASTICSEARCH_USER_PASSWORD is not the expected value of ${LOG_ELASTICSEARCH_PASSWORD}."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_USER_PASSWORD is the expected value."
  fi

  [[ "${BAD_FTS_ELASTIC}" == "0" ]] && checkIsValidElastic "${IS_FTS_ELASTICSEARCH_HOSTNAME}" "FTS_ELASTICSEARCH_HOSTNAME" "${IS_FTS_ELASTICSEARCH_USERNAME}" "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}"

}

checkISLicenseStatus() {
  if ! IS_INT_ROLE=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get svc platform-int -o jsonpath='{.spec.selector.role}' 2>/dev/null); then
    logMessage "IS platform pods not found - skipping license check."
    return
  fi
  if ! IS_RESTAPI_POD_STATUS=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get pod "platform-${IS_INT_ROLE}-0" -o jsonpath='{.status.containerStatuses[?(@.name=="platform")].ready}'); then
    logMessage "IS platform-${IS_INT_ROLE}-0 pod not found - skipping license check."
    return
  fi
  if [ "${IS_RESTAPI_POD_STATUS}" == "false" ]; then
    logMessage "IS platform-${IS_INT_ROLE}-0 pod not ready - skipping license check."
    return
  fi
  logMessage "Checking IS license status..."
  getISAdminCreds
  if ! getISJWT; then
    logError "176" "Failed to authenticate user ${IS_ADMIN_USER} - can't check IS license status."
    return
  fi
  getISLicense
}

getISJWT() {
  ARJWT=$(${CURL_BIN} -sk -X POST "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/jwt/login" -H "content-type/x-www-form" -d "username=${IS_ADMIN_USER}&password=${IS_ADMIN_PASSWD}")
  if echo "${ARJWT}" | grep -q "ERROR"; then
    return 1
  else
    return 0
  fi
}

getISLicense() {
  IS_LICENSE_TYPE=$(${CURL_BIN} -sk "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/arsys/v1/entry/AR%20System%20Administration%3A%20Server%20Information?q=%27configurationName%27%3D%22%25%22&fields=values(licensetype)" -H "Authorization: AR-JWT $ARJWT" | ${JQ_BIN} -r '.entries[0].values.licensetype')
  if [ "${IS_LICENSE_TYPE}" != "AR Server" ]; then
    logWarning "020" "IS Server does not have a permanent license - current license type is ${IS_LICENSE_TYPE}."
  else
    logMessage "IS Server is licensed."
  fi
}

getISAdminCreds() {
  IS_ADMIN_USER=hannah_admin
  IS_ADMIN_PASSWD=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret atriumwebsvc -o jsonpath='{.data.UDDI_ADMIN_PASSWORD}' | ${BASE64_BIN} -d )
}

checkAssistTool() {
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get deployment assisttool-dep > /dev/null 2>&1 ; then
    logMessage "Support Assistant Tool found - checking for fpackager sidecar containers..."
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.containers[*].name}' | grep -q fpackager ; then
      logError "177" "fpackager sidecar containers not found - Support Assistant will not be able to access application logs."
    else
      logMessage "fpackager sidecar containers are present."
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get role assisttool-rl > /dev/null 2>&1 ; then
      logError "178" "assisttool-rl role not found - Support Assistant will not be able to access application logs."
    else
      logMessage "assisttool-rl role present in Helix IS namespace."
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get rolebinding assisttool-rlb > /dev/null 2>&1 ; then
      logError "178" "assisttool-rlb rolebinding not found - Support Assistant will not be able to access application logs."
    else
      logMessage "assisttool-rlb rolebinding present in Helix IS namespace."
    fi
  else
    logMessage "Support Assistant Tool is not deployed."
  fi
}

buildJISQLcmd() {
  case ${IS_DB_TYPE} in
    mssql)
      JISQLJAR=sqljdbc4.jar
      JISQLURL=jdbc:sqlserver://${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}
      JISQLDRIVER=mssql
      ;;
    oracle)
      # Note SQL in section below has newline before go command to workaround Java OOM error for jisql with Oracle
      JISQLJAR=ojdbc8.jar
      JISQLURL=jdbc:oracle:thin:@//${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${IS_ORACLE_SERVICE_NAME}
      JISQLDRIVER=oraclethin
      ;;
    postgres)
      JISQLJAR=postgresql-42.2.8.jar
      JISQLURL=jdbc:postgresql://${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${IS_AR_DB_NAME}
      JISQLDRIVER=postgresql
      ;;
  esac
  JISQLCMD="${JAVA_BIN} -cp ./jisql.jar:./${JISQLJAR} com.xigole.util.sql.Jisql -user ${IS_AR_DB_USER} -password ${IS_AR_DB_PASSWORD} -driver ${JISQLDRIVER} -cstring ${JISQLURL} -noheader -query"
}

testNetConnection () {
  if ! ${NC_BIN} -z -w 5 "${1}" "${2}" > /dev/null 2>&1; then
    return 1
  else
    return 0
fi
}

checkISDBSettings() {
  if ! testNetConnection "${IS_DATABASE_HOST_NAME}" "${IS_DB_PORT}"; then
    logWarning "027" "IS DB server (${IS_DATABASE_HOST_NAME}) is not reachable on port ${IS_DB_PORT} - skipping DB checks."
    SKIP_SR_DB_CHECKS=1
    return
  else
    logMessage "IS DB server (${IS_DATABASE_HOST_NAME}) is reachable on port ${IS_DB_PORT}."
  fi
  checkISDBLatency
  if [ -z "${IS_AR_DB_USER}" ] || [ -z "${IS_AR_DB_PASSWORD}" ]; then
    logWarning "021" "One or more DB settings are blank - skipping checks."
    return
  fi
  if [ -f dbjars.tgz ]; then
    logMessage "Found dbjars.tgz - running DB checks."
    logMessage "Unpacking dbjars.tgz..."
    ${TAR_BIN} zxf dbjars.tgz
    buildJISQLcmd
    logMessage "Connecting to ${JISQLURL} as ${IS_AR_DB_USER}..."
    # Note - new line is needed to avoid Java heap errors from jisql
    SQL_RESULT=$($JISQLCMD "select currDbVersion from control
    go" 2>&1)

    if echo "${SQL_RESULT}" | grep -q ErrorCode ; then
     logError "180" "Problem connecting to database - please review the following message."
     echo "${SQL_RESULT}"
     return
    else
      DB_VERSION=$(echo "${SQL_RESULT}" | awk '{print $1}')
      if [ ! -z "${IS_DB_VERSION}" ]; then
        if [ "${DB_VERSION}" != "${IS_DB_VERSION}" ]; then
          logError "181" "Database is not the expected version - found ${DB_VERSION} but should be ${IS_DB_VERSION}."
        else
          logMessage "Database is the expected version - ${DB_VERSION}."
        fi
      else
        logMessage "Database currDbVersion is ${DB_VERSION}."
      fi
    fi

    # Specific DB type checks
    case "${IS_DB_TYPE}" in
      mssql)
        SQL_RESULT=$(${JISQLCMD} "SELECT name FROM sys.synonyms
        go" 2>&1)
        if ! echo "${SQL_RESULT}" | grep -q trace_xe_action_map; then
            logError "182" "Missing 'trace_xe_action_map' synonym in database - please refer to the BMC docs."
        fi
        if ! echo "${SQL_RESULT}" | grep -q trace_xe_event_map; then
            logError "182" "Missing 'trace_xe_event_map' synonym in database - please refer to the BMC docs."
        fi
        ;;
    esac

  else
    logMessage "DB jar files not found - skipping checks.  Download dbjars.tgz to the HITT directory to enable them..."
  fi
}

checkSRDBSettings() {
  echo TODO
}


isIPAddress() {
  if [[ "${1}" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]]; then
    echo 0
  else
    echo 1
  fi
}

reportResults() {
  echo ""
  logStatus "HITT Summary Report"
  echo "==================="
  if [ $FAIL -gt 0 ] || [ $WARN -gt 0 ] ; then
    echo -e "${BOLD}${FAIL} errors / ${WARN} warnings found - please review the ${HITT_MSG_FILE} file for more details and suggested fixes.${NORMAL}"
    echo ""
    if [ "${#ERROR_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${RED}ERRORS:${NORMAL}"
      printf '%s\n' "${ERROR_ARRAY[@]}"
    fi
    if [ "${#WARN_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${YELLOW}WARNINGS:${NORMAL}"
      printf '%s\n' "${WARN_ARRAY[@]}"
    fi
    echo "==================="
    echo -e "${BOLD}Please review the ${GREEN}${HITT_MSG_FILE}${NORMAL}${BOLD} file for explanations and suggested fixes for the messages above.${NORMAL}"
    echo -e "${BOLD}Attach the ${YELLOW}hittlogs.zip${NORMAL}${BOLD} file to your case if working with BMC Support.${NORMAL}"
  else
    echo -e "${BOLD}Tests complete - no errors or warnings found.${NORMAL}"
  fi
}

checkKubeconfig() {
  KUBECONFIG_ERROR=0
  if ! ${KUBECTL_BIN} version > /dev/null 2>&1; then
    logError "184" "'kubectl version' command returned an error - unable to continue." 1
  fi
  if [ ! -z "${KUBECONFIG}" ] && [ "${KUBECONFIG}" != "${HOME}/.kube/config" ]; then
    logError "185" "KUBECONFIG environment variable is set (${KUBECONFIG}) but is not the default of ${HOME}/.kube/config required by Jenkins."
    KUBECONFIG_ERROR=1
  fi
  if [ ! -f ~/.kube/config ]; then
    logError "186" "Default KUBECONFIG file (~/home/.kube/config) required by Jenkins pipelines not found."
    KUBECONFIG_ERROR=1
  fi
  if [ ${KUBECONFIG_ERROR} == "0" ]; then
    logMessage "Local KUBECONFIG file appears valid."
  fi
}

getRegistryDetailsFromHP() {
  getRegistryDetailsFromSecret "${HP_NAMESPACE}" "bmc-dtrhub"
  HP_REGISTRY_SERVER="${REGISTRY_SERVER}"
  HP_REGISTRY_USERNAME="${REGISTRY_USERNAME}"
  HP_REGISTRY_PASSWORD="${REGISTRY_PASSWORD}"
}

getRegistryDetailsFromSecret() {
  # namespace secret_name
  REGISTRY_SERVER=""
  REGISTRY_USERNAME=""
  REGISTRY_PASSWORD=""
  IMAGESECRET_JSON=$(${KUBECTL_BIN} -n "${1}" get secret "${2}" -o jsonpath='{.data.\.dockerconfigjson}' | ${BASE64_BIN} -d)
  if [ "${IMAGESECRET_JSON}" = "" ]; then
    logError "187" "Failed to get registry details from ${2} secret in ${1} namespace."
    SKIP_REGISTRY=1
    return
  fi
  REGISTRY_SERVER=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].key')
  REGISTRY_USERNAME=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].value.username')
  REGISTRY_PASSWORD=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].value.password')
}

getRegistryDetailsFromIS() {
  if [ "${IS_IMAGESECRET_NAME}" = "" ]; then
    SKIP_REGISTRY=1
    return
  fi
  getRegistryDetailsFromSecret "${IS_NAMESPACE}" "${IS_IMAGESECRET_NAME}"
  IS_SECRET_HARBOR_REGISTRY_HOST="${REGISTRY_SERVER}"
  IS_SECRET_IMAGE_REGISTRY_USERNAME="${REGISTRY_USERNAME}"
  IS_SECRET_IMAGE_REGISTRY_PASSWORD="${REGISTRY_PASSWORD}"
}

checkHPRegistryDetails() {
  getRegistryDetailsFromHP
  logMessage "Helix Platform IMAGE_REGISTRY_HOST is ${HP_REGISTRY_SERVER} and IMAGE_REGISTRY_USERNAME is ${HP_REGISTRY_USERNAME}."
}

checkISDBLatency() {
  if [ "${IS_DATABASE_HOST_NAME}" == "" ]; then
    logMessage "DATABASE_HOST_NAME not set - can't test IS DB latency."
    return
  fi
  logMessage "Testing latency between cluster and IS DB server ${IS_DATABASE_HOST_NAME}."
  PING_POD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pod --no-headers -l app=rsso -o custom-columns=:metadata.name --field-selector status.phase=Running | head -1)
  if [ ! -z "${PING_POD}" ]; then
    PING_RESULT=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PING_POD}" -- ping "${IS_DATABASE_HOST_NAME}" -c 3 -q | tail -1)
    if echo "${PING_RESULT}" | grep -q "^round-trip" ; then
      IS_DB_LATENCY=$(echo "${PING_RESULT}" | cut -d '/' -f 4)
      logMessage "IS DB latency from cluster is ${IS_DB_LATENCY}ms."
      if compare "${IS_DB_LATENCY} < 1" ; then logMessage "Latency is ${BOLD}GOOD${NORMAL}."; fi ; return
      if compare "${IS_DB_LATENCY} < 3" ; then logMessage "Latency is ${BOLD}AVERAGE${NORMAL}."; fi ; return
      if compare "${IS_DB_LATENCY} < 6" ; then logMessage "Latency is ${BOLD}POOR${NORMAL}. Performance may be impacted."; fi ; return
      if compare "${IS_DB_LATENCY} > 6" ; then logMessage "Latency is ${BOLD}VERY POOR${NORMAL}. Performance will be impacted."; fi ; return
    else
      logError "188" "Unexpected response from IS DB ping test ${PING_RESULT}."
    fi
  fi
}

checkISDockerLogin() {
  SKIP_REGISTRY=0
  getRegistryDetailsFromIS
  if [ "${SKIP_REGISTRY}" == "1" ]; then
    logError "189" "Failed to get IS registry details - skipping checks."
    return
  fi

  if [ "${MODE}" == "pre-is" ]; then
    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${IS_SECRET_HARBOR_REGISTRY_HOST}" ]; then
      logError "190" "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) does not match the value in the registry secret (${IS_SECRET_HARBOR_REGISTRY_HOST})."
      return
    fi
    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" ]; then
      logError "190" "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) does not match the value in the registry secret (${IS_SECRET_IMAGE_REGISTRY_USERNAME})."
      return
    fi
#    if [ "${IS_IMAGE_REGISTRY_PASSWORD}" != "${IS_SECRET_IMAGE_REGISTRY_PASSWORD}" ]; then
#      logError "IMAGE_REGISTRY_PASSWORD does not match the value in the registry secret."
#      return
#    fi
  fi

  if ! docker ps > /dev/null 2>&1; then
    if ! which docker > /dev/null 2>&1 ; then
      LOG_MSG="'docker' command not found in path"
    else
      LOG_MSG="'docker' command returned an error"
    fi
    logWarning "022" "${LOG_MSG} - skipping registry credentials check."
    return
  fi
  if docker login "${IS_SECRET_HARBOR_REGISTRY_HOST}" -u "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" -p "${IS_SECRET_IMAGE_REGISTRY_PASSWORD}" > /dev/null 2>&1 ; then
    logMessage "IMAGE_REGISTRY credentials are valid - docker login to ${IS_SECRET_HARBOR_REGISTRY_HOST} was successful."
  else
    logError "192" "'docker login' to ${IS_SECRET_HARBOR_REGISTRY_HOST} failed - please check credentials."
  fi
}

dumpVARs() {
  [[ ${CREATE_LOGS} -eq 0 ]] && return
  rm -f "${VALUES_LOG_FILE}"
  # Debug mode to print all variables
  if [ "${MODE}" == "pre-is" ]; then
    echo "CUSTOMER_SERVICE=${ISP_CUSTOMER_SERVICE}" >> "${VALUES_LOG_FILE}"
    echo "ENVIRONMENT=${ISP_ENVIRONMENT}" >> "${VALUES_LOG_FILE}"
    for i in "${PIPELINE_VARS[@]}"; do
      v="IS_${i}"
      echo "${i}=${!v}" >> "${VALUES_LOG_FILE}"
    done
  fi
  if [ "${MODE}" == "post-is" ]; then
    createPipelineVarsArray
    for i in "${PIPELINE_VARS[@]}"; do
      v="IS_${i}"
      if [ "${!v}" != "" ]; then
        echo "${i}=${!v}" >> "${VALUES_LOG_FILE}"
      fi
    done
  fi
}

checkJenkinsConfig() {
  [[ "${SKIP_JENKINS}" == 1 ]] && return
  logMessage "Checking plugins..."
  checkJenkinsPlugins
  logMessage "Checking nodes..."
  checkJenkinsNodes
  logMessage "Checking global pipeline libraries..."
  checkJenkinsGlobalLibs
  logMessage "Checking credentials..."
  validateJenkinsCredentials
}

checkJenkinsNodes() {
  NODE_STATUS=$(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/manage/computer/api/json?depth=1")
  OFFLINE_NODES=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[]| select(.offline=='true').displayName')
  if [ ! -z "${OFFLINE_NODES}" ] ; then
    logError "193" "One or more Jenkins nodes found in an 'offline' state."
    printf '%s\n' "${OFFLINE_NODES}"
  fi

  NODE_LABELS=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[].assignedLabels[].name')
  if ! echo "${NODE_LABELS}" | grep -q 'ansible-master' ; then
    logError "194" "No Jenkins nodes found with the 'ansible-master' label."
  fi
}

checkJenkinsPlugins() {
  # token-macro email-ext jira
  EXPECTED_PLUGINS=(
    apache-httpcomponents-client-4-api
    bootstrap5-api
    bouncycastle-api
    branch-api
    caffeine-api
    checks-api
    cloudbees-folder
    commons-lang3-api
    commons-text-api
    credentials
    credentials-binding
    display-url-api
    durable-task
    echarts-api
    font-awesome-api
    git
    git-client
    instance-identity
    ionicons-api
    jackson2-api
    jakarta-activation-api
    jakarta-mail-api
    javax-activation-api
    javax-mail-api
    jaxb
    jquery3-api
    junit
    mailer
    mask-passwords
    matrix-project
    mina-sshd-api-common
    mina-sshd-api-core
    parameter-separator
    pipeline-build-step
    pipeline-groovy-lib
    pipeline-input-step
    pipeline-milestone-step
    pipeline-model-api
    pipeline-model-definition
    pipeline-model-extensions
    pipeline-stage-step
    pipeline-stage-tags-metadata
    plain-credentials
    plugin-util-api
    rebuild
    resource-disposer
    scm-api
    script-security
    snakeyaml-api
    ssh-credentials
    ssh-slaves
    structs
    trilead-api
    validating-string-parameter
    variant
    workflow-aggregator
    workflow-api
    workflow-basic-steps
    workflow-cps
    workflow-durable-task-step
    workflow-job
    workflow-multibranch
    workflow-scm-step
    workflow-step-api
    workflow-support
    ws-cleanup
    pipeline-utility-steps
    pipeline-stage-view
    pipeline-rest-api
    )
  JK_PLUGINS=$(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/pluginManager/api/json?depth=1" | ${JQ_BIN} -r '.plugins[].shortName')
  for i in "${EXPECTED_PLUGINS[@]}" ; do
    if ! echo "${JK_PLUGINS}" | grep -wq "${i}" ; then
      logError "195" "Jenkins plugin '${i}' is missing."
    fi
  done
}

checkJenkinsCredentials() {
  # Get list of credentials and check for expected IDs
  EXPECTED_CREDENTIALS=(github ansible_host ansible kubeconfig TOKENS)
   #password_vault_apikey)
  JK_CREDS=$(${CURL_BIN} -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/credentials/api/json?depth=3"  | ${JQ_BIN} -r '.stores.system.domains._.credentials[].id')
  for i in "${EXPECTED_CREDENTIALS[@]}" ; do
    if ! echo "${JK_CREDS}" | grep -wq "${i}" ; then
      logError "196" "Jenkins credentials with id '${i}' is missing."
    fi
  done
}

checkForNewHITT() {
  if [  $(${CURL_BIN} -o /dev/null --silent -Iw '%{http_code}' "${HITT_URL}") == "200" ]; then
    REMOTE_MD5=$(${CURL_BIN} -sL "${HITT_URL}" | md5sum | awk '{print $1}')
    LOCAL_MD5=$(md5sum $0 | awk '{print $1}')
    if [ "$REMOTE_MD5" != "$LOCAL_MD5" ]; then
      logStatus "${GREEN}An updated version of HITT is available - please see https://bit.ly/gethitt or update by running:\n${YELLOW}curl -sL https://bit.ly/hitt-sh -o hitt.sh${NORMAL}"
      echo
      read -rsn1 -p"Press any key to continue or Ctrl+C to cancel..."
      echo
    fi
  fi
}

unpackSSLPoke() {
  echo "${SSLPOKE_PAYLOAD}" | tr -d ' ' | base64 -d > SSLPoke.class
}

checkHITTconf() {
  CONF_UPDATED=0
  while IFS="=" read -r param value; do
    if ! grep "^${param}" "${1}" >/dev/null 2>&1; then
      echo "${param}=${value}" >> "${1}"
      CONF_UPDATED=1
    fi
  done < <(grep '.=' .hitt.conf)
  [[ $CONF_UPDATED == 1 ]] && logStatus "${GREEN}HITT config file (${1}) has been updated with a new parameter.${NORMAL}"
}

createPipelineNamesArray() {
  PIPELINE_NAMES=(
    HELIX_ONPREM_DEPLOYMENT
    HELIX_GENERATE_CONFIG
    HELIX_PLATFORM_DEPLOY
    HELIX_NON_PLATFORM_DEPLOY
    HELIX_CONFIGURE_ITSM
    HELIX_SMARTAPPS_DEPLOY
    HELIX_ITSM_INTEROPS
    SUPPORT_ASSISTANT_TOOL
    HELIX_FULL_STACK_UPGRADE
    HELIX_PLATFORM_UPDATE
    HELIX_NON_PLATFORM_UPDATE
  )
}

getKubeconfigFromJenkins() {
  SCRIPT='import com.cloudbees.plugins.credentials.*;
    import com.cloudbees.plugins.credentials.domains.Domain;
    import org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl;
    def idName = "kubeconfig"
    SystemCredentialsProvider.getInstance().getCredentials().stream().
      filter { cred -> cred instanceof FileCredentialsImpl }.
      map { fileCred -> (FileCredentialsImpl) fileCred }.
      filter { fileCred -> idName.equals( fileCred.getId() ) }.
      forEach { fileCred ->
        String s = new String( fileCred.getSecretBytes().getPlainData() )
        println ""
        println s
        println ""
      }'

  runJenkinsCurl "${SCRIPT}"
}

validateJenkinsKubeconfig() {
  getKubeconfigFromJenkins > kubeconfig.jenkins
  if [ ! -s ./kubeconfig.jenkins ]; then
    logWarning "028" "Failed to extract kubeconfig file from Jenkins - skipping validation."
    return
  fi
  if ! KUBECONFIG=./kubeconfig.jenkins ${KUBECTL_BIN} cluster-info > /dev/null 2>>${HITT_DBG_FILE}; then
    logError "197" "Jenkins KUBECONFIG credential does not appear contain a valid kubeconfig file."
  else
    logMessage "Jenkins KUBECONFIG credential contains a valid kubeconfig file."
  fi
}

getJenkinsGlobalLibs() {
  SCRIPT='import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import org.jenkinsci.plugins.workflow.libs.GlobalLibraries
    def jenkins = Jenkins.get()
    def globalLibraries = GlobalLibraries.get()
    def libraryDetails = globalLibraries.libraries.collect { lib ->
        return [
            name       : lib.name,
            defaultVersion: lib.defaultVersion,
            retrieverType : lib.retriever?.class?.simpleName,
            implicit   : lib.implicit
        ]
    }
    def jsonOutput = JsonOutput.toJson(libraryDetails)
    println(JsonOutput.prettyPrint(jsonOutput))'

  runJenkinsCurl "${SCRIPT}"
}

checkJenkinsGlobalLibs() {
  JLIBS_JSON=$(getJenkinsGlobalLibs)
  JENKINS_LIBS=(pipeline-framework JENKINS-27413-workaround-library)
  MISSING_LIBS=""
  for i in "${JENKINS_LIBS[@]}" ; do
    LIB_NAME=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${i}'").name')
    if [ "${LIB_NAME}" != "${i}" ]; then
      MISSING_LIBS+=" '${i}'"
    else
      LIB_VERSION=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${i}'").defaultVersion')
      LIB_TYPE=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${i}'").retrieverType')
      LIB_IMPLICIT=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${i}'").implicit')
      if [ "${LIB_VERSION}" != "master" ]; then
        logError "150" "The 'Default version' of the '${LIB_NAME}' library is not the expected value of 'master'."
      fi
      if [ "${LIB_TYPE}" != "SCMSourceRetriever" ]; then
        logError "179" "The 'Retrieval method' of the '${LIB_NAME}' library is not the expected value 'Modern SCM'."
      fi
      case "${LIB_NAME}" in
        pipeline-framework)
          if [ "${LIB_IMPLICIT}" != "false" ]; then
            logError "171" "The 'Load implicity' option of the '${LIB_NAME}' library should not be selected."
          fi
          ;;
        JENKINS-27413-workaround-library)
          if [ "${LIB_IMPLICIT}" != "true" ]; then
            logError "171" "The 'Load implicity' option of the '${LIB_NAME}' library should be selected."
          fi
          ;;
        esac
    fi
  done
  if [ "${MISSING_LIBS}" != "" ]; then
    logError "183" "One or more Jenkins global pipeline libraries not found -${MISSING_LIBS}"
  else
    logMessage "Expected global pipeline libraries found in Jenkins."
  fi
}

getJenkinsCredentials() {
  SCRIPT='import jenkins.model.*
    import com.cloudbees.plugins.credentials.*
    import com.cloudbees.plugins.credentials.domains.*
    def credentialsStore = Jenkins.instance.getExtensionList(
        "com.cloudbees.plugins.credentials.SystemCredentialsProvider"
    ).first().getStore()
    def credentialsList = []
    credentialsStore.getDomains().each {
        domain -> credentialsStore.getCredentials(domain).each {
            credential -> if (credential instanceof com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials) {
                credentialsList.add([
                    id: credential.id,
                    username: credential.username,
                    type: credential.getClass().getSimpleName(),
                    scope: credential.getScope(),
                    password: credential.password.plainText
                ])
            } else {
                credentialsList.add([
                    id: credential.id,
                    type: credential.getClass().getSimpleName(),
                    scope: credential.getScope()
                ])
            }
        }
    }
    println groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(credentialsList))'

  runJenkinsCurl "${SCRIPT}"
}

validateJenkinsCredentials() {
  JCREDS_JSON=$(getJenkinsCredentials)
  MISSING_CREDS=""
  for i in "${JENKINS_CREDS[@]}" ; do
    ID=$(echo "${JCREDS_JSON}" | ${JQ_BIN} -r '.[] | select(.id=="'${i}'").id')
    if [ "${ID}" != "${i}" ]; then
      MISSING_CREDS+=" '${i}'"
    else
      SCOPE=$(echo "${JCREDS_JSON}" | ${JQ_BIN} -r '.[] | select(.id=="'${i}'").scope')
      CRED_TYPE=$(echo "${JCREDS_JSON}" | ${JQ_BIN} -r '.[] | select(.id=="'${i}'").type')
      if [ "${SCOPE}" != "GLOBAL" ]; then
        logError "121" "The scope setting for the Jenkins credentials object '${ID}' is '${SCOPE}' but it should be 'GLOBAL'."
      fi
      if [ "${CRED_TYPE}" == "UsernamePasswordCredentialsImpl" ]; then
        CRED_PWD=$(echo "${JCREDS_JSON}" | ${JQ_BIN} -r '.[] | select(.id=="'${i}'").password')
        CRED_USER=$(echo "${JCREDS_JSON}" | ${JQ_BIN} -r '.[] | select(.id=="'${i}'").username')
        if [ "${CRED_PWD}" == "" ]; then
          logError "183" "The password for the '${ID}' credential is blank but should be set to the password of the user '${CRED_USER}'."
        fi
      fi
    fi
  done
  if [ "${MISSING_CREDS}" != "" ]; then
    logError "198" "One or more Jenkins credentials not found -${MISSING_CREDS}"
  else
    logMessage "Expected credentials found in Jenkins."
  fi

  if echo "${MISSING_CREDS}" | grep -vq kubeconfig ; then
    validateJenkinsKubeconfig
  fi
}

checkPlatformAdminExtSvc() {
PLATFORM_EXT_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get svc platform-admin-ext -o json)
PLATFORM_EXT_SVC_TYPE=$(echo ${PLATFORM_EXT_JSON} | ${JQ_BIN} -r '.spec.type' )

case "${PLATFORM_EXT_SVC_TYPE}" in
  ClusterIP)
    PLATFORM_EXT_IP=$(echo ${PLATFORM_EXT_JSON} | ${JQ_BIN} '.spec.externalIPs | length' )
    if [ "${PLATFORM_EXT_IP}" == "0" ]; then
      logWarning "025" "Helix IS platform-admin-ext service is of type ClusterIP but does not appear to have an externalIP assigned."
    else
      logMessage "Helix IS platform-admin-ext service is of type ClusterIP."
    fi
    ;;
  NodePort)
    logMessage "Helix IS platform-admin-ext service is of type NodePort."
    ;;
  *)
    logWarning "026" "Helix IS platform-admin-ext service is of type '${PLATFORM_EXT_SVC_TYPE}' and not the expected ClusterIP or NodePort."
    ;;
esac
}

getPods() {
  # ns name
  logMessage "Getting pods from ${1}..."
  ${KUBECTL_BIN} -n ${1} get pods -o wide > k8s-get-pods-${1}.log
}

getEvents() {
  # ns name
  logMessage "Getting events from ${1}..."
  ${KUBECTL_BIN} -n ${1} events --sort-by='.lastTimestamp' 2>/dev/null > k8s-events-${1}.log
}

getMessageJSON() {
  # msg id
  MSG_JSON=$(echo "${ALL_MSGS_JSON}" | ${JQ_BIN} '.[] | select(.id=="'"${1}"'")')
  if [ -z "${MSG_JSON}" ]; then
    MSG_JSON="{\"id\": \"$1\",\"cause\": \"Message details not found for id $1.\", \"impact\": \"Message details cannot be displayed.\", \"remediation\": \"Please report to 'mark_walters@bmc.com'\"}"
  fi
}

getMessageDetails() {
  eval "export $(printf "%s\n" "${MSG_JSON}" | ${JQ_BIN} -r 'to_entries | map("\(.key)=\(.value)") | @sh')"
}

printMessageDetails() {
  printf "\n"
  printf "${BOLD}Message:${NORMAL} ${MSG}\n"
  printf "${BOLD}${YELLOW}Cause:${NORMAL} ${cause}\n"
  printf "${BOLD}${RED}Impact:${NORMAL} ${impact}\n"
  printf "${BOLD}${GREEN}Remediation:${NORMAL} ${remediation}\n"
}

logMessageDetails() {
  # MSG_ID
  getMessageJSON "${1}"
  getMessageDetails
  printMessageDetails >> "${HITT_MSG_FILE}"
}

checkJenkinsCLIJavaVersion() {
  REQUIRED_VERSION=$(${UNZIP_BIN} -p jenkins-cli.jar META-INF/MANIFEST.MF | grep ^Build-Jdk-Spec | cut -d ' ' -f2)
  if compare "${JAVA_VERSION} < ${REQUIRED_VERSION//[^[:alnum:]]/}"; then
    logError "207" "Jenkins CLI tool requires Java ${REQUIRED_VERSION//[^[:alnum:]]/} but HITT is using Java ${JAVA_VERSION}. Please install, or configure HITT to use, the later version."
  fi
}

isJmespathInstalled() {
  if ! ansible-playbook /dev/stdin << EOF >/dev/null 2>&1
  - hosts: localhost
    gather_facts: false
    tasks:
    - pip:
        name: jmespath
        state: present
EOF
  then
    return 1
  else
    return 0
  fi
}

versionFmt() {
  printf "%03d%03d" $(echo "$1" | tr '.' ' ')
}

checkDERequirements() {
  IS_MAJOR_VERSION="${IS_VERSION:2:2}"

  # if IS <=22.x then kubectl must be <= 1.27
  if [ "${IS_MAJOR_VERSION}" -lt 23 ]; then
    MAX_KUBECTL_VERSION="1.27"
    INSTALLED_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.clientVersion.major + "." + .clientVersion.minor')
    if compare "${INSTALLED_VERSION} > ${MAX_KUBECTL_VERSION}"; then
      logError "103" "kubectl must be version ${MAX_KUBECTL_VERSION} or less to support the '--short' option - currently installed version is ${INSTALLED_VERSION}."
    fi
  fi

  # ansible checks
  if ! which ansible > /dev/null 2>&1 ; then
    logWarning "029" "'ansible' command not found - skipping checks."
  else
    if [ "${IS_MAJOR_VERSION}" -eq 22 ]; then
      MAX_ANSIBLE_VERSION="2.9"
    elif [ "${IS_MAJOR_VERSION}" -eq 23 ]; then
      MAX_ANSIBLE_VERSION="2.15"
    fi

    ANSIBLE_VERSION=$(ansible --version 2>/dev/null | head -1 | grep -oP '\d+.\d+')
    if [ $(versionFmt "${ANSIBLE_VERSION}") -gt $(versionFmt "${MAX_ANSIBLE_VERSION}") ]; then
      logError "208" "The installed version of ansible (${ANSIBLE_VERSION}) is not supported - required version must be no greater than ${MAX_ANSIBLE_VERSION}."
    else
      logMessage "Using ansible version - ${ANSIBLE_VERSION}"
      if ! isJmespathInstalled ; then
        ANSIBLE_PYTHON_VERSION=$(ANSIBLE_STDOUT_CALLBACK=json ansible -m setup localhost 2>/dev/null | sed -n '/^{/,/^}/p' | ${JQ_BIN} -r .plays[0].tasks[0].hosts.localhost.ansible_facts.ansible_python.executable)
        logError "209" "Unable to verify that 'jmespath' is installed for the python instance used by ansible (${ANSIBLE_PYTHON_VERSION})."
      fi
    fi

    ANSIBLE_CFG_FILE=/etc/ansible/ansible.cfg
    ANSIBLE_CFG_MISSING=""
    if [ ! -f "${ANSIBLE_CFG_FILE}" ]; then
      logError "210" "Ansible configuration file (${ANSIBLE_CFG_FILE}) not found - skipping checks."
    else
      logMessage "Checking ansible configuration file - ${ANSIBLE_CFG_FILE}."
      ANSIBLE_CFG_VALS=(bin_ansible_callbacks=true callback_whitelist=profile_tasks stdout_callback=yaml host_key_checking=false ssh_args=-ocontrolmaster=auto retries=3 pipelining=true)
      ANSIBLE_CFG=$(cat /etc/ansible/ansible.cfg | tr -d ' ')
      for i in "${ANSIBLE_CFG_VALS[@]}"; do
      	if ! echo "${ANSIBLE_CFG}" |  grep -qi "${i}" ; then
           ANSIBLE_CFG_MISSING+="${i%%=*}=, "
        fi
      done
      if [ -n "${ANSIBLE_CFG_MISSING}" ]; then
        logError "210" "One or more settings in the ansible configuration file are missing, or have an unexpected value - '${ANSIBLE_CFG_MISSING::-2}'."
      fi
    fi
  fi
}

getJenkinsCrumb() {
  JENKINS_CRUMB=$(${CURL_BIN} -c .cookies -sk "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/crumbIssuer/api/json" | ${JQ_BIN} -r .crumb )
}

runJenkinsCurl() {
  #1 groovy script
  ${CURL_BIN} -b .cookies --data-urlencode "script=${1}" -sv -H "Jenkins-Crumb:${JENKINS_CRUMB}" "${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/scriptText" 2>>${HITT_DBG_FILE}
}

# FUNCTIONS End

# MAIN Start
main() {

NOW=$(date)
logStatus "Welcome to the Helix IS Triage Tool - ${NOW}."
logStatus "Checking KUBECONFIG file..."
checkKubeconfig

# config file checks
if [ ! -f "${HITT_CONFIG_FILE}" ]; then
  if ! ${KUBECTL_BIN} get ns > /dev/null 2>&1 ; then
    createHITTconf "${HITT_CONFIG_FILE}"
    logError "199" "'kubectl get namespaces' command returned unexpected results - please update the HITT config file (${HITT_CONFIG_FILE}) manually." 1
  fi
  NS_ARRAY=($(${KUBECTL_BIN} get ns --no-headers -o custom-columns=':.metadata.name'))
  logStatus "HITT config file (${HITT_CONFIG_FILE}) not found - creating..."
  logStatus "Please use the following steps to configure the HITT and create your config file..."
  getConfValues
  createHITTconf "${HITT_CONFIG_FILE}"
else
  createHITTconf ".hitt.conf"
  checkHITTconf "${HITT_CONFIG_FILE}"
fi
source "${HITT_CONFIG_FILE}"
checkForNewHITT

# Run tctl command and then exit
if [[ ! -z "${TCTL_CMD}" ]]; then
  logStatus "Running in tctl only mode..."
  deleteTCTLJob
  deployTCTL "${TCTL_CMD}"
  logMessage "tctl output is...\n"
  getTCTLOutput full
  echo "${TCTL_OUTPUT}"
  deleteTCTLJob
  exit
fi

# Validate action
[[ "${MODE}" =~ ^post-hp$|^pre-is$|^post-is$ ]] || usage

# MODE is required
if [[ -z ${MODE} ]]; then
  logError "200" "Mode must be specified with -m <post-hp|pre-is|post-is>" 1
fi

if [ "${MODE}" == "post-hp" ]; then
  SKIP_JENKINS=1
else
  if [ -n "${JENKINS_USERNAME}" ]; then
    JENKINS_PASSWORD=$(printf %s "${JENKINS_PASSWORD}" | ${JQ_BIN} -sRr @uri)
    JENKINS_CREDENTIALS="${JENKINS_USERNAME}:${JENKINS_PASSWORD}@"
  fi
fi

# Check required variables are settings
checkVars
logStatus "${BOLD}Starting HITT in ${MODE} mode...${NORMAL}"

# Check command line tools present
logStatus "Checking for required tools in path..."
checkRequiredTools
# Remove
cleanUp start
logStatus "Checking namespaces..."
if [ "${HP_NAMESPACE}" == "${IS_NAMESPACE}" ]; then
  logError "201" "Helix Platform and Helix IS should be installed in their own namespaces." 1
fi
checkHPNamespace "${HP_NAMESPACE}"
getPods ${HP_NAMESPACE}
getEvents ${HP_NAMESPACE}
if [ "${MODE}" != "post-hp" ]; then
  checkISNamespace "${IS_NAMESPACE}"
  getPods ${IS_NAMESPACE}
  getEvents ${IS_NAMESPACE}
fi
logStatus "Getting versions..."
getVersions
setVarsFromPlatform
checkHelixLoggingDeployed
logStatus "Checking Helix Platform registry details..."
checkHPRegistryDetails
logStatus "Getting RSSO details..."
getRSSODetails
logStatus "Getting domain..."
getDomain
logStatus "Getting tenant details from Helix Platform..."
getTenantDetails
logStatus "Checking for ITSM services in Helix Platform..."
checkServiceDetails
logStatus "Checking FTS Elasticsearch cluster status..."
checkFTSElasticStatus
logStatus "Getting realm details from RSSO..."
getRealmDetails
logStatus "Checking realm..."
checkTenantRealms
validateRealm

if [ "${MODE}" != "post-hp" ]; then
  logStatus "Checking Jenkins is accessible..."
  checkJenkinsIsRunning
  logStatus "Checking Jenkins configuration..."
  checkJenkinsConfig
  logStatus "Getting IS details..."
  getISDetailsFromK8s
  getISDetailsFromJenkins
  logStatus "Checking IS details..."
  validateISDetails
  checkPipelinePwds
  logStatus "Checking IS registry details..."
  checkISDockerLogin
  logStatus "Checking IS cacerts..."
  validateCacerts
  logStatus "Checking IS License..."
  checkISLicenseStatus
fi

if [ "${MODE}" == "pre-is" ]; then
  logStatus "Checking Deployment Engine setup..."
  checkDERequirements
fi

if [ "${SKIP_JENKINS}" == "0" ]; then
  logStatus "Checking IS FTS Elastic settings..."
  checkFTSElasticSettings
  logStatus "Checking IS DB settings..."
  checkISDBSettings
fi

if [ "${MODE}" == "post-is" ]; then
  logStatus "Checking Helix IS platform-admin-ext service..."
  checkPlatformAdminExtSvc
  logStatus "Checking Support Assistant Tool..."
  checkAssistTool
fi

cleanUp stop
reportResults
# DEBUG only
dumpVARs
if [ "${MODE}" != "post-hp" ]; then
  saveAllPipelineConsoleOutput
fi
[ -f "${HITT_LOG_FILE}" ] && cat "${HITT_LOG_FILE}" | sed -e 's/\x1b\[[0-9;]*m//g' > hitt.txt
[ -f "${HITT_MSG_FILE}" ] && cat "${HITT_MSG_FILE}" | sed -e 's/\x1b\[[0-9;]*m//g' > hittmsgs.txt
${ZIP_BIN} -q - *.log hitt*.txt k8s*.txt > hittlogs.zip
}

# Set vars and process command line
SCRIPT_VERSION=1
HITT_CONFIG_FILE=hitt.conf
HITT_URL=https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh
FAIL=0
WARN=0
SKIP_JENKINS=0
CREATE_LOGS=1
HITT_LOG_FILE=hitt.log
HITT_DBG_FILE=hittdebug.log
HITT_MSG_FILE=hittmsgs.log
VALUES_LOG_FILE=values.log
CLEANUP_DIRS=(configsrepo)
CLEANUP_FILES=(sealcacerts sealstore.p12 sealstore.pem kubeconfig.jenkins)
CLEANUP_START_FILES=("${HITT_MSG_FILE}" "${HITT_DBG_FILE}")
CLEANUP_STOP_FILES=()
REQUIRED_TOOLS=(kubectl curl keytool openssl jq base64 git java tar nc host zip unzip)
IS_ALIAS_SUFFIXES=(smartit sr is restapi atws dwp dwpcatalog vchat chat int)
JENKINS_CREDS=(github ansible_host ansible kubeconfig TOKENS password_vault_apikey)
BOLD="\e[1m"
NORMAL="\e[0m"
RED="\e[31m"
YELLOW="\e[33m"
GREEN="\e[32m"
SEALTCTL=sealtctl
KUBECTL_BIN=kubectl
JQ_BIN=jq
ERROR_ARRAY=()
WARN_ARRAY=()
JENKINS_CREDENTIALS=""
SSLPOKE_PAYLOAD="
yv66vgAAADcAbQoAFgAjCQAkACUHACYKACcAKBIAAAAsCgAtAC4KACQALwoACQAwBwAxCgAyADMK
AAkANAcANQoADAA2CgAMADcKACAAOAoAHwA5CgAfADoKAC0AOwgAPAcAPQoAFAA+BwA/AQAGPGlu
aXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABG1haW4BABYoW0xqYXZhL2xhbmcv
U3RyaW5nOylWAQANU3RhY2tNYXBUYWJsZQcAQAcAQQcAQgEAClNvdXJjZUZpbGUBAAxTU0xQb2tl
LmphdmEMABcAGAcAQwwARABFAQAHU1NMUG9rZQcARgwARwBIAQAQQm9vdHN0cmFwTWV0aG9kcw8G
AEkIAEoMAEsATAcATQwATgBPDABQAFEMAFIAUwEAHmphdmF4L25ldC9zc2wvU1NMU29ja2V0RmFj
dG9yeQcAVAwAVQBWDABXAFgBABdqYXZheC9uZXQvc3NsL1NTTFNvY2tldAwAWQBaDABbAFwMAF0A
UQwAXgBfDABgAF8MAGEAUQEAFlN1Y2Nlc3NmdWxseSBjb25uZWN0ZWQBABNqYXZhL2xhbmcvRXhj
ZXB0aW9uDABiABgBABBqYXZhL2xhbmcvT2JqZWN0AQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAE2ph
dmEvaW8vSW5wdXRTdHJlYW0BABRqYXZhL2lvL091dHB1dFN0cmVhbQEAEGphdmEvbGFuZy9TeXN0
ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBAA9qYXZhL2xhbmcvQ2xhc3MBAAdnZXRO
YW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsKAGMAZAEAFlVzYWdlOiABIDxob3N0PiA8cG9ydD4B
ABdtYWtlQ29uY2F0V2l0aENvbnN0YW50cwEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFu
Zy9TdHJpbmc7AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9T
dHJpbmc7KVYBAARleGl0AQAEKEkpVgEACmdldERlZmF1bHQBABsoKUxqYXZheC9uZXQvU29ja2V0
RmFjdG9yeTsBABFqYXZhL2xhbmcvSW50ZWdlcgEACHBhcnNlSW50AQAVKExqYXZhL2xhbmcvU3Ry
aW5nOylJAQAMY3JlYXRlU29ja2V0AQAmKExqYXZhL2xhbmcvU3RyaW5nO0kpTGphdmEvbmV0L1Nv
Y2tldDsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAPZ2V0T3V0
cHV0U3RyZWFtAQAYKClMamF2YS9pby9PdXRwdXRTdHJlYW07AQAFd3JpdGUBAAlhdmFpbGFibGUB
AAMoKUkBAARyZWFkAQAFcHJpbnQBAA9wcmludFN0YWNrVHJhY2UHAGUMAEsAaQEAJGphdmEvbGFu
Zy9pbnZva2UvU3RyaW5nQ29uY2F0RmFjdG9yeQcAawEABkxvb2t1cAEADElubmVyQ2xhc3NlcwEA
mChMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5nL1N0cmlu
ZztMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9s
YW5nL09iamVjdDspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7BwBsAQAlamF2YS9sYW5nL2lu
dm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxl
cwAhAAMAFgAAAAAAAgABABcAGAABABkAAAAdAAEAAQAAAAUqtwABsQAAAAEAGgAAAAYAAQAAAAkA
CQAbABwAAQAZAAAA9gAEAAUAAABsKr4FnwAXsgACEgO2AAS6AAUAALYABgS4AAe4AAjAAAlMKyoD
MioEMrgACrYAC8AADE0stgANTiy2AA46BBkEBLYADy22ABCeABCyAAIttgARtgASp//vsgACEhO2
AAanAAxMK7YAFQS4AAexAAEAGgBfAGIAFAACABoAAABCABAAAAALAAYADAAWAA0AGgAQACEAEQAy
ABMANwAUAD0AFwBDABkASgAaAFcAHABfACEAYgAeAGMAHwBnACAAawAiAB0AAAAoAAUa/wAoAAUH
AB4HAAkHAAwHAB8HACAAABP/AAoAAQcAHgABBwAUCAADACEAAAACACIAaAAAAAoAAQBmAGoAZwAZ
ACkAAAAIAAEAKgABACs="
ALL_MSGS_JSON="[
  {
    \"id\": \"001\",
    \"cause\": \"The kubectl command used to list namespaces in the cluster did not return the expected list of namespace names.\",
    \"impact\": \"Some later tests to validate the namespaces will not be run.\",
    \"remediation\": \"Verify the output by running kubectl get ns at the command prompt and check with cluster admins if additional permissions are needed.\"
  },
  {
    \"id\": \"002\",
    \"cause\": \"The DEPLOYMENT_SIZE used for the Helix Platform is expected to be one of itsmcompact/itsmsmall/itsmxlarge if the Platform is only providing the common services used by Helix Service Management. Other options are valid if additional ITOM components, such as BHOM or BHCO, are in use or planned.\",
    \"impact\": \"Additional cluster resources may be used if the sizing is incorrect.\",
    \"remediation\": \"Confirm the Helix Platform sizing choice and redeploy if a change is required.\"
  },
  {
    \"id\": \"003\",
    \"cause\": \"Helix Logging is not installed but the option to enable the log shipper is set in the bmc-helix-logging.config file.\",
    \"impact\": \"Helix Platform pod log output will include a lot of errors reporting that fluent-bit is not available which makes it difficult to use for troubleshooting.\",
    \"remediation\": \"Install Helix Logging or set the ENABLE_LOG_SHIPPER_IN_PODS option to false in helix-on-prem-deployment-manager/configs/bmc-helix-logging.config file and redeploy.\"
  },
  {
    \"id\": \"004\",
    \"cause\": \"The Tenant value in the RSSO realm created for Helix Service Management is recommended to be set to the tenant ID using the name.number format.\",
    \"impact\": \"Other values are valid but you must use this as the TENANT_DOMAIN in the Jenkins HELIX_ONPREM_DEPLOYMENT pipeline. If these values are different there will be issues with Helix Service Management apps logins.\",
    \"remediation\": \"Use the recommended name.number format or ensure that the same value is used as the Jenkins HELIX_ONPREM_DEPLOYMENT pipeline TENANT_DOMAIN value.\"
  },
  {
    \"id\": \"005\",
    \"cause\": \"The Helix Portal alias is not present in the Helix Service Management RSSO realm. This alias is added during the Jenkins HELIX_ITSM_INTEROPS pipeline run.\",
    \"impact\": \"The alias is not present until the Jenkins HELIX_ITSM_INTEROPS pipeline is run but, if it is missing after this, there will be errors when logging in.\",
    \"remediation\": \"If the alias has been removed after the Jenkins HELIX_ITSM_INTEROPS pipeline has been run, add the full portal FQDN to the Applications Domain in the Helix Service Management SSO realm.\"
  },
  {
    \"id\": \"006\",
    \"cause\": \"The last build of the HELIX_ONPREM_DEPLOYMENT pipeline, or one of the deployment pipelines it runs, was not successful.\",
    \"impact\": \"The problematic pipeline may not have completed all the stages necessary to deploy the Helix Service Management products.\",
    \"remediation\": \"Review the pipeline console output in Jenkins, or the log files in the HITT directory, to try and identify the cause. Other HITT errors are likely to help with this.\"
  },
  {
    \"id\": \"007\",
    \"cause\": \"The Helix Service Management deployment size is M or above which means that platform-int pods will be created. By default, these pods do not run the normalization plugin which may be called by some types of activity.\",
    \"impact\": \"API calls to the platform-int pods which invoke the Atrium normalization engine plugin will fail with an error such as ERROR (8760): Cannot establish a network connection to the AR System Plug-In server; platform-int-0.platform-int:9555\",
    \"remediation\": \"Select the ENABLE_PLATFORM_INT_NORMALIZATION option to enable the plugin for the platform-int pods. If deployment is complete see KA000405995 for changes to the ENABLE_AR_SERVICES variable in the platform-int statefulset.\"
  },
  {
    \"id\": \"008\",
    \"cause\": \"The CUSTOM_BINARY_PATH option in the HELIX_ONPREM_DEPLOYMENT pipeline is selected but this is rarely required.\",
    \"impact\": \"Deployment may fail unless the CUSTOM_BINARY_PATH is a valid path that provides the expected binary files.\",
    \"remediation\": \"Deselect the CUSTOM_BINARY_PATH option unless you are certain that it is required.\"
  },
  {
    \"id\": \"009\",
    \"cause\": \"The IS_CLOUD option is selected which will cause public cloud systems to provision an external load balancer.\",
    \"impact\": \"This setting is used with public cloud providers to automatically provision a load balancer for the environment.\",
    \"remediation\": \"The option may be valid if you want your cloud provider to create a load balancer for you.\"
  },
  {
    \"id\": \"010\",
    \"cause\": \"The ROUTE_ENABLED and/or ROUTE_TLS_ENABLED options are selected but it is documented that they should be left unselected.\",
    \"impact\": \"These options are not valid for onprem use and should not be selected.\",
    \"remediation\": \"Deselect the options.\"
  },
  {
    \"id\": \"011\",
    \"cause\": \"The kubectl get ingressclasses command to list ingressclasses in the cluster did not work as expected.\",
    \"impact\": \"Some later tests to validate ingresses will not be run.\",
    \"remediation\": \"Verify the output by running kubectl get ingressclasses at the command prompt and check with cluster admins if additional permissions are needed.\"
  },
  {
    \"id\": \"012\",
    \"cause\": \"The HELIX_ITSM_INSIGHTS application is selected for installation but the ITSM Insights services are not installed in the Helix Platform.\",
    \"impact\": \"The ITSM Insights application will not work.\",
    \"remediation\": \"Deselect the HELIX_ITSM_INSIGHTS option or install ITSM Insights services in the Helix Platform.\"
  },
  {
    \"id\": \"013\",
    \"cause\": \"The option to integrate ITSM Insights with the Helix Platform is selected but HELIX_ITSM_INSIGHTS is not selected to install the application.\",
    \"impact\": \"A link to launch ITSM Insights will be added to the Helix Portal but the application will be not installed.\",
    \"remediation\": \"Select, or deselect, both BMC_HELIX_ITSM_INSIGHTS and HELIX_ITSM_INSIGHTS depending on whether ITSM Insights is required.\"
  },
  {
    \"id\": \"014\",
    \"cause\": \"The option to enable the Support Assistant fpackager sidecar containers is not selected. This is required for Support Assistant to be able to access Helix Service Management application logs.\",
    \"impact\": \"Support Assistant Tool will not be able to access application logs.\",
    \"remediation\": \"Select the SIDECAR_SUPPORT_ASSISTANT_FPACK option.\"
  },
  {
    \"id\": \"015\",
    \"cause\": \"The option to create the role and rolebinding required for the Support Assistant Tool is not selected.\",
    \"impact\": \"Support Assistant Tool will not be able to access application logs unless the steps to create them manually are followed.\",
    \"remediation\": \"Select the SUPPORT_ASSISTANT_CREATE_ROLE or see the product documentation for steps to create the role and rolebinding manually.\"
  },
  {
    \"id\": \"016\",
    \"cause\": \"The option to deploy the fluent-bit sidecar pods is enabled but Helix Logging is not installed.\",
    \"impact\": \"The fluent-bit sidecars will be created but will not send the logs they monitor to the Helix Logging Elasticsearch for viewing via Kibana.\",
    \"remediation\": \"Deselect the SIDECAR_FLUENTBIT option unless you plan to install Helix Logging later.\"
  },
  {
    \"id\": \"017\",
    \"cause\": \"The cacerts Java keystore file was not attached to the Jenkins HELIX_ONPREM_DEPLOYMENT pipeline. Most customers are expected to attach this file.\",
    \"impact\": \"If custom CA signed certificates are in use the deployment will fail.\",
    \"remediation\": \"Attach the cacerts with your custom CA certificate chain added using the CACERTS_FILE option in Jenkins. This may not be necessary if using certificates purchased direct from Digicert.\"
  },
  {
    \"id\": \"018\",
    \"cause\": \"The FTS_ELASTICSEARCH_HOSTNAME value is an IP address rather than the recommended servicename.namespace format.\",
    \"impact\": \"An IP address is valid if the service has been exposed but it is recommended to use the servicename.namespace format.\",
    \"remediation\": \"Either servicename.namespace or an IP address is valid but the former avoids having to add an externalIP to the service used for FTS.\"
  },
  {
    \"id\": \"019\",
    \"cause\": \"The value is an IP address rather than the recommended servicename.namespace format.\",
    \"impact\": \"An IP address is valid if the service has been exposed but it is recommended to use the servicename.namespace format.\",
    \"remediation\": \"Either servicename.namespace or an IP address is valid but the former avoids having to add an externalIP to the service.\"
  },
  {
    \"id\": \"020\",
    \"cause\": \"The IS server does not have a permanent license.\",
    \"impact\": \"If not already completed, the HELIX_SMARTAPPS_DEPLOY and HELIX_ITSM_INTEROPS pipelines may fail as the temporary 3 day server license has expired.\",
    \"remediation\": \"The temporary IS server license, valid for three days from the first time the server is started, has expired. Apply a valid server license.\"
  },
  {
    \"id\": \"021\",
    \"cause\": \"Either or both the AR_DB_USER and AR_DB_PASSWORD values are blank.\",
    \"impact\": \"This will cause a fresh installation to fail and prevent HITT from running some later checks.\",
    \"remediation\": \"Set the values in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"022\",
    \"cause\": \"Either the docker command was not found or docker login to the IMAGE_REGISTRY_HOST failed.\",
    \"impact\": \"The registry server credentials will not be validated.\",
    \"remediation\": \"Run the docker login command from the command prompt and resolve the error to enable the checks.\"
  },
  {
    \"id\": \"023\",
    \"cause\": \"The platform-admin-ext service in the Helix Service Management namespace does not have an externalIP assigned.\",
    \"impact\": \"Developer Studio and other AR API clients will not be able to connect to the system. Upgrades will fail as they require this type of connectivity.\",
    \"remediation\": \"See the post installation configuration steps in the documentation for steps to expose an externalIP or set the PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS value in the pipeline.\"
  },
  {
    \"id\": \"024\",
    \"cause\": \"The AR_DB_CASE_SENSITIVE option is selected but the database type is not Postgres and/or the DATABASE_RESTORE option is not selected. This option is only valid when the pipeline is used to restore a Postgres database.\",
    \"impact\": \"For MSSQL/Oracle databases this option is always ignored and the case-sensitivity of the system is determined by the database dump that was restored. For Postgres the option controls which dump is restored by the pipeline, it is ignored unless DATABASE_RESTORE is also selected.\",
    \"remediation\": \"Ensure you have selected the correct options, or restored the appropriate database dump, to achieve the required case-sensitivity for your system.\"
  },
  {
    \"id\": \"025\",
    \"cause\": \"The platform-admin-ext service does not have an external IP address assigned.\",
    \"impact\": \"Connectivity via the service for AR API clients such as Developer Studio will not be possible and upgrades will fail.\",
    \"remediation\": \"Use the steps in the Performing the postinstallation configurations documentation to add an externalIP to the service.\"
  },
  {
    \"id\": \"026\",
    \"cause\": \"The platform-admin-ext service is not one of the expected types of ClusterIP or NodePort.\",
    \"impact\": \"Connectivity via the service for AR API clients such as Developer Studio may not be possible and upgrades may fail.\",
    \"remediation\": \"Review the platform-admin-ext service configuration in the cluster and revert any customisations.\"
  },
  {
    \"id\": \"027\",
    \"cause\": \"The DATABASE_HOST_NAME is not reachable from the Deployment Engine on the DB_PORT.\",
    \"impact\": \"Later checks to validate the database will not be run and deployment will fail if either of the values are wrong.\",
    \"remediation\": \"Verify the DATABASE_HOST_NAME/DB_PORT values and enable connectivity from the Deployment Engine if possible.\"
  },
  {
    \"id\": \"028\",
    \"cause\": \"A command to extract and save the kubeconfig file from the Jenkins kubeconfig credential failed to return the expected result.\",
    \"impact\": \"A check to confirm that it is a valid kubeconfig file for the cluster will not be run.\",
    \"remediation\": \"Confirm the kubeconfig credential exists and has a valid file attached.\"
  },
  {
    \"id\": \"029\",
    \"cause\": \"Ansible command was not found on the path of the user running HITT.\",
    \"impact\": \"Checks to validate the ansible version and dependencies will not be run and Helix Service Management deployment will not be possible.\",
    \"remediation\": \"Run the Deployment Engine setup script or install the recommended version of ansible using the OS package manager.\"
  },
  {
    \"id\": \"030\",
    \"cause\": \"HITT 'pre-is' mode is used to validate the environment and HELIX_ONPREM_DEPLOYMENT pipeline values before deployment but the DEPLOYMENT_MODE is not the expected value of 'FRESH'.\",
    \"impact\": \"HITT checks may return incorrect results.\",
    \"remediation\": \"Confirm the DEPLOYMENT_MODE is correct and review any warnings/errors carefully as the results may be unreliable.\"
  },
  {
    \"id\": \"031\",
    \"cause\": \"The IS_DATABASE_ALWAYS_ON option is only applicable when the DB_TYPE is 'mssql'.  It has no effect for other database types.\",
    \"impact\": \"The setting will be ignored.\",
    \"remediation\": \"Deselect the IS_DATABASE_ALWAYS_ON option.\"
  },
  {
    \"id\": \"032\",
    \"cause\": \"When the IS_DATABASE_ALWAYS_ON option is selected you must be using an MSSQL AlwaysOn database system.\",
    \"impact\": \"If the database is not an MSSQL AlwaysOn system then deployment will fail.\",
    \"remediation\": \"Confirm the IS database is an MSSQL AlwaysOn system and that the other DB options refer to the AlwaysOn listener.\"
  },
  {
    \"id\": \"033\",
    \"cause\": \"The ENABLE_PLATFORM_INT_NORMALIZATION option is ignored from 23.3.03 onwards as there is a dedicated normalization engine pod.\",
    \"impact\": \"The selected option has no effect.\",
    \"remediation\": \"The selected option has no effect.\"
  },
  {
    \"id\": \"034\",
    \"cause\": \"There are Kubernetes resourcequotas defined for the named namespace.\",
    \"impact\": \"If the quotas are too low deployments may fail.\",
    \"remediation\": \"Review the resourcequotas and verify that they are high enough for the planned deployment.\"
  },
  {
    \"id\": \"100\",
    \"cause\": \"The hitt.conf file exists but is missing some required values.\",
    \"impact\": \"The HITT script cannot run with an incomplete configuration.\",
    \"remediation\": \"Edit the hitt.conf file and enter the missing values or delete the file and rerun the script to be prompted for them.\"
  },
  {
    \"id\": \"101\",
    \"cause\": \"The wrong version of a required tool is installed. HITT requires a specific version, or later, of this tool to run.\",
    \"impact\": \"The HITT script cannot run with the currently installed version.\",
    \"remediation\": \"Install the required version.\"
  },
  {
    \"id\": \"102\",
    \"cause\": \"At least one pod in the namespace is not in a ready state.\",
    \"impact\": \"Installation may fail if one of the pods that the applications depend on are not ready.\",
    \"remediation\": \"Check the namespace to understand why the reported pod is not ready. Note there are some cronjob pods which run every few minutes and seeing one of these in a ContainerCreating state is not likely to cause a problem.\"
  },
  {
    \"id\": \"103\",
    \"cause\": \"The deployment scripts for this version of Helix Service Management use 'kubectl version --short=true' commands but the the '--short' flag has been removed from the installed version of kubectl.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Install version 1.27 of kubectl on the Deployment Engine.\"
  },
  {
    \"id\": \"104\",
    \"cause\": \"The product option named in the error message has been selected but it depends on another product which has not been selected.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Review the product documentation and make sure that all dependent options are also selected.\"
  },
  {
    \"id\": \"105\",
    \"cause\": \"One of command line tools that HITT requires to run has not been found.\",
    \"impact\": \"HITT cannot run without this command line tool.\",
    \"remediation\": \"Install the missing tool or update the hitt.conf file with the full path to the tool it is already installed.\"
  },
  {
    \"id\": \"106\",
    \"cause\": \"One of the Helix namespaces cannot be found in the cluster.\",
    \"impact\": \"HITT requires valid namespaces names to be able to run.\",
    \"remediation\": \"Create the namespace or set the correct value in the hitt.conf file.\"
  },
  {
    \"id\": \"107\",
    \"cause\": \"A check used to validate the namespace type failed to find the expected components in the namespace.\",
    \"impact\": \"HITT requires valid namespaces names to be able to run.\",
    \"remediation\": \"Update the hitt.conf file with the correct name for the namespace.\"
  },
  {
    \"id\": \"108\",
    \"cause\": \"The HELIX_GENERATE_CONFIG pipeline must have been run to create the image registry secret specified in the IMAGESECRET_NAME value.\",
    \"impact\": \"When run in this mode HITT requires that the IMAGESECRET_NAME image registry secret has been created.\",
    \"remediation\": \"Populate the values in the HELIX_ONPREM_DEPLOYMENT pipeline and build it with the HELIX_GENERATE_CONFIG option selected.\"
  },
  {
    \"id\": \"109\",
    \"cause\": \"An unknown version of the Helix Service Management applications has been found.\",
    \"impact\": \"HITT is unable to run as it does not know which checks are valid for this version.\",
    \"remediation\": \"Check the HITT website for an update that supports this version.\"
  },
  {
    \"id\": \"110\",
    \"cause\": \"The value of the named infra.config setting in the Helix Platform is the same as the alias that will be used for the Helix Service Management MidTier.\",
    \"impact\": \"Installation will complete but the MidTier will not be usable due to the conflict.\",
    \"remediation\": \"Either redeploy the Helix Platform with a different value or change one/both of the CUSTOMER_SERVICE and ENVIRONMENT values to make the MidTier alias different to the LB_HOST.\"
  },
  {
    \"id\": \"111\",
    \"cause\": \"This version of the Helix Platform uses a new credentials service which must be installed, or the use of disabled in the TMS deployment, before the HELIX_ITSM_INTEROPS pipeline can be run.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail due to the missing/misconfigured service.\",
    \"remediation\": \"See https://community.bmc.com/s/article/Helix-ITSM-OnPrem-HELIX-ITSM-INTEROPS-pipeline-fails-with-INTERNAL-SERVER-ERROR-when-using-Helix-Platform-24-2\"
  },
  {
    \"id\": \"112\",
    \"cause\": \"The RSSO system did not return the expected admin token.\",
    \"impact\": \"HITT is unable to continue without the RSSO admin token which is needed to read values from the Helix Platform.\",
    \"remediation\": \"Resolve the issue reported in the message and rerun the HITT script.\"
  },
  {
    \"id\": \"113\",
    \"cause\": \"The Helix Logging Elasticsearch system did not return the expected 'green' response to a health check query.\",
    \"impact\": \"Helix Logging may not be functional but this will not prevent the installation of Helix Service Management.\",
    \"remediation\": \"Helix Service Management may be installed but the problem should be investigated.\"
  },
  {
    \"id\": \"114\",
    \"cause\": \"No valid tenants were found in the Helix Platform.\",
    \"impact\": \"HITT cannot continue without the tenant details.\",
    \"remediation\": \"Review the Helix Platform deployment.log for issues and use the tctl command to verify the tenant status.\"
  },
  {
    \"id\": \"115\",
    \"cause\": \"The sealtctl Kubernetes job used to read the tenant details from the Helix Platform failed to run.\",
    \"impact\": \"HITT cannot continue without the tenant details which are needed for later checks.\",
    \"remediation\": \"Review the Helix Platform pods for issues and use the tctl command to verify the tenant status.\"
  },
  {
    \"id\": \"116\",
    \"cause\": \"The expected realm name was not found under the SAAS_TENANT in SSO.\",
    \"impact\": \"HITT cannot continue without a valid realm to use for checks.\",
    \"remediation\": \"Make sure that the realm was created for the SAAS_TENANT and that the IS_CUSTOMER_SERVICE and IS_ENVIRONMENT values in the hitt.conf file are correct.\"
  },
  {
    \"id\": \"117\",
    \"cause\": \"The Helix Service Management realm was found under the Helix Platform tenant in SSO when it should be configured for the SAAS_TENANT.\",
    \"impact\": \"Helix Service Management logins will fail.\",
    \"remediation\": \"Delete the realm under the Helix Platform tenant and create it for the SAAS_TENANT.\"
  },
  {
    \"id\": \"118\",
    \"cause\": \"The arHost value for the realm is not the expected value of platform-user-ext.HELIX-IS-NAMESPACE.\",
    \"impact\": \"Helix Service Management logins will fail.\",
    \"remediation\": \"Correct the arHost value to the expected value.\"
  },
  {
    \"id\": \"119\",
    \"cause\": \"The arPort value for the realm is not the required value.\",
    \"impact\": \"Helix Service Management logins will fail.\",
    \"remediation\": \"Correct the arPort value in the realm Authentication page to 46262.\"
  },
  {
    \"id\": \"120\",
    \"cause\": \"One of the Helix Service Management aliases is missing from the Application Domains list in the realm.\",
    \"impact\": \"The missing service will not be usable.\",
    \"remediation\": \"Add the missing alias to the Application Domains list in the realm.\"
  },
  {
    \"id\": \"121\",
    \"cause\": \"Jenkins credentials objects have a scope setting which should be set to 'GLOBAL' but this object has a different value.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins browse to Manage Jenkins -> Credentials, select the object named in the error message -> Update, and change the Scope to 'Global' via the drop down menu.\"
  },
  {
    \"id\": \"122\",
    \"cause\": \"A DNS entry for the specified alias was not found or the use of the 'host' command to validate the alias failed.\",
    \"impact\": \"Installation may fail and the application accessed via the alias may not be accessible.\",
    \"remediation\": \"Add the missing alias to DNS if needed or check the output of the command 'host alias' to see what the error was.\"
  },
  {
    \"id\": \"123\",
    \"cause\": \"The sealtcl Kubernetes job used to confirm that the required ARSERVICES are installed in the Helix Platform failed to return the expected response.\",
    \"impact\": \"If the Helix Platform was installed with ARSERVICES=no the HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"If the Helix Platform was installed with ARSERVICES=yes in the deployment.config file this error can be ignored, otherwise you should update the Helix Platform to install them.\"
  },
  {
    \"id\": \"124\",
    \"cause\": \"The required ITSM services are not installed in the Helix Platform, likely because the ARSERVICES option in the deployment.config was not set to yes.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Rerun the Helix Platform deployment-manager.sh script with ARSERVICES=yes to install the missing services.\"
  },
  {
    \"id\": \"125\",
    \"cause\": \"The Helix Platform service used provide FTS indexing has not returned the expected response to health check.\",
    \"impact\": \"The Helix Service Management platform-* pods will not be able to start and installation will fail or the applications will be unavailable.\",
    \"remediation\": \"Check the status of the pods providing the service and address any issues.\"
  },
  {
    \"id\": \"126\",
    \"cause\": \"A running Jenkins server was not found at the URL shown.\",
    \"impact\": \"Jenkins data and configuration tests cannot be run.\",
    \"remediation\": \"Confirm that Jenkins is running and that the related settings in the hitt.conf file are correct.\"
  },
  {
    \"id\": \"127\",
    \"cause\": \"The Jenkins server requires authentication but HITT was not able to login using the credentials in the hitt.conf file.\",
    \"impact\": \"Jenkins data and configuration tests cannot be run.\",
    \"remediation\": \"Review the Jenkins settings in the hitt.conf file and update them if needed.  Remember to enclose the password in double quotes to avoid problems with special characters.\"
  },
  {
    \"id\": \"128\",
    \"cause\": \"One or both of the CUSTOMER_SERVICE/ENVIRONMENT values in the HELIX_ONPREM_DEPLOYMENT pipeline are blank.\",
    \"impact\": \"HITT cannot continue without the missing values.\",
    \"remediation\": \"Rebuild the HELIX_ONPREM_DEPLOYMENT pipeline, enter the missing values, then rerun HITT.\"
  },
  {
    \"id\": \"129\",
    \"cause\": \"The git command to clone the CUSTOMER_CONFIGS repository failed to run as expected.\",
    \"impact\": \"Some checks which validate data from the CUSTOMER_CONFIGS repo will not be run.\",
    \"remediation\": \"Run the 'git clone path_to_customer_configs_repo' command manually and resolve any problems reported before rerunning HITT.\"
  },
  {
    \"id\": \"130\",
    \"cause\": \"The input configuration file created by the HELIX_GENERATE_CONFIG pipeline was not found in the CUSTOMER_CONFIGS git repository.\",
    \"impact\": \"Some later checks to validate values in the input configuration file will not be run.\",
    \"remediation\": \"Ensure that the HELIX_GENERATE_CONFIG pipeline has been run to create the input configuration file.\"
  },
  {
    \"id\": \"131\",
    \"cause\": \"A required value in the HELIX_ONPREM_DEPLOYMENT pipeline is blank.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Rebuild the HELIX_ONPREM_DEPLOYMENT pipeline, enter the missing values, then rerun HITT.\"
  },
  {
    \"id\": \"132\",
    \"cause\": \"The TENANT_DOMAIN value in the HELIX_ONPREM_DEPLOYMENT pipeline is not the same as the Tenant value in the SSO realm.\",
    \"impact\": \"Helix Service Management logins will fail.\",
    \"remediation\": \"Correct the TENANT_DOMAIN value in the HELIX_ONPREM_DEPLOYMENT so that it matches the Tenant value in the SSO realm.\"
  },
  {
    \"id\": \"133\",
    \"cause\": \"The RSSO_URL value in the HELIX_ONPREM_DEPLOYMENT pipeline does not match that used by the Helix Platform.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Correct the RSSO_URL value in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"134\",
    \"cause\": \"The AR_SERVER_APP_SERVICE_PASSWORD in the HELIX_ONPREM_DEPLOYMENT pipeline is too long. The maximum length is 19 characters.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Shorten the value to no more than 19 characters.\"
  },
  {
    \"id\": \"135\",
    \"cause\": \"The password value in the HELIX_ONPREM_DEPLOYMENT pipeline is too long.  The maximum length is 20 characters.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Shorten the value to no more than 20 characters.\"
  },
  {
    \"id\": \"136\",
    \"cause\": \"The AR_SERVER_MIDTIER_SERVICE_PASSWORD in the HELIX_ONPREM_DEPLOYMENT pipeline is too long.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Shorten the value to no more than 20 characters.\"
  },
  {
    \"id\": \"137\",
    \"cause\": \"The CLUSTER value in the HELIX_ONPREM_DEPLOYMENT pipeline is not found as a context in the kubeconfig file.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Update the CLUSTER value in the HELIX_ONPREM_DEPLOYMENT pipeline to the correct context from your kubeconfig file. Use 'kubectl config get-contexts' to list valid options.\"
  },
  {
    \"id\": \"138\",
    \"cause\": \"The IS_NAMESPACE value in the HELIX_ONPREM_DEPLOYMENT pipeline does not match the IS_NAMESPACE set in the hitt.conf file.\",
    \"impact\": \"Some HITT checks may be invalid or fail.\",
    \"remediation\": \"Set the correct IS_NAMESPACE value in the HELIX_ONPREM_DEPLOYMENT pipeline or update the hitt.conf file.\"
  },
  {
    \"id\": \"139\",
    \"cause\": \"The IS_NAMESPACE value in the HELIX_ONPREM_DEPLOYMENT pipeline is too long.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Use a namespace name that is no longer than the value in the message.\"
  },
  {
    \"id\": \"140\",
    \"cause\": \"The CUSTOMER_SERVICE and/or ENVIRONMENT values in the HELIX_ONPREM_DEPLOYMENT pipeline do not match those set in the hitt.conf file.\",
    \"impact\": \"Some HITT checks may be invalid or fail.\",
    \"remediation\": \"Set the correct values in the HELIX_ONPREM_DEPLOYMENT pipeline, or update the hitt.conf file, and rerun HITT.\"
  },
  {
    \"id\": \"141\",
    \"cause\": \"The INGRESS_CLASS value in the HELIX_ONPREM_DEPLOYMENT pipeline is blank or is not a valid ingressclass in the cluster.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set the correct INGRESS_CLASS value in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"142\",
    \"cause\": \"The CLUSTER_DOMAIN value in the HELIX_ONPREM_DEPLOYMENT pipeline is different to the DOMAIN used for the Helix Platform.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"The Helix Service Management and Helix Platform are expected to use the same domain. Verify and correct the CLUSTER_DOMAIN value in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"143\",
    \"cause\": \"For onprem deployments the only valid option for the INPUT_CONFIG_METHOD in the HELIX_ONPREM_DEPLOYMENT pipeline is 'Generate_Input_File'.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set INPUT_CONFIG_METHOD in the HELIX_ONPREM_DEPLOYMENT pipeline to 'Generate_Input_File'.\"
  },
  {
    \"id\": \"144\",
    \"cause\": \"The HELM_NODE value in the HELIX_ONPREM_DEPLOYMENT pipeline is blank but should be set to a valid node name.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set the HELM_NODE to a valid value as detailed in the BMC documentation.\"
  },
  {
    \"id\": \"145\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT pipeline value for HELM_NODE is not a valid node in Jenkins.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set the HELM_NODE to a valid value as detailed in the BMC documentation.\"
  },
  {
    \"id\": \"146\",
    \"cause\": \"For onprem deployment the only valid option for the REGISTRY_TYPE in the HELIX_ONPREM_DEPLOYMENT pipeline is 'DTR'.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set the REGISTRY_TYPE in the HELIX_ONPREM_DEPLOYMENT pipeline to 'DTR'.\"
  },
  {
    \"id\": \"147\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT pipelines deploy some containers in the Helix Platform namespace which requires that the HARBOR_REGISTRY_HOST and IMAGE_REGISTRY_HOST are the same.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Use the same value for the HARBOR_REGISTRY_HOST in the HELIX_ONPREM_DEPLOYMENT pipeline as the Helix Platform IMAGE_REGISTRY_HOST.\"
  },
  {
    \"id\": \"148\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT pipeline value for the IMAGE_REGISTRY_USERNAME is different to the value used for the Helix Platform which will cause problems with the HELIX_ITSM_INTEROPS pipeline.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Use the same value for the IMAGE_REGISTRY_USERNAME in the HELIX_ONPREM_DEPLOYMENT pipeline as set in the Helix Platform infra.config file.\"
  },
  {
    \"id\": \"149\",
    \"cause\": \"The DB_SSL_ENABLED option in the HELIX_ONPREM_DEPLOYMENT pipeline is selected but this is not currently supported for onprem use.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Deselect the DB_SSL_ENABLED option in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"150\",
    \"cause\": \"The named global pipeline library should have a 'Default version' of 'master' but it is set to something else.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins browse to Manage Jenkins -> System, find the pipeline library and change the 'Default version' to 'master'.\"
  },
  {
    \"id\": \"151\",
    \"cause\": \"The LOGS_ELASTICSEARCH_TLS option in the HELIX_ONPREM_DEPLOYMENT pipeline is not selected but this is required.\",
    \"impact\": \"Logs will not be sent to the Helix Logging system.\",
    \"remediation\": \"Select the LOGS_ELASTICSEARCH_TLS option in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"152\",
    \"cause\": \"The LOGS_ELASTICSEARCH_PASSWORD in the HELIX_ONPREM_DEPLOYMENT pipeline must match the KIBANA_PASSWORD set in the Helix Platform secrets.txt.\",
    \"impact\": \"Logs will not be sent to the Helix Logging system.\",
    \"remediation\": \"Set the LOGS_ELASTICSEARCH_PASSWORD in the HELIX_ONPREM_DEPLOYMENT pipeline to the same value as the KIBANA_PASSWORD set in the Helix Platform secrets.txt and efk-elasticsearch-kibana secret.\"
  },
  {
    \"id\": \"153\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT pipeline value for the IMAGE_REGISTRY_PASSWORD is different to the value used for the Helix Platform which will cause problems with the HELIX_ITSM_INTEROPS pipeline.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Use the same value for the IMAGE_REGISTRY_PASSWORD in the HELIX_ONPREM_DEPLOYMENT pipeline as set in the Helix Platform secrets.txt file.\"
  },
  {
    \"id\": \"154\",
    \"cause\": \"The VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME in the HELIX_ONPREM_DEPLOYMENT pipeline are the same or blank when they must be set to different values.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME to different values.\"
  },
  {
    \"id\": \"155\",
    \"cause\": \"The PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS value in the HELIX_ONPREM_DEPLOYMENT pipeline should be blank, or one or more, comma separated IP addresses enclosed in square brackets.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set the PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS value to the correct format - for example [192.1.2.100]\"
  },
  {
    \"id\": \"156\",
    \"cause\": \"The RSSO_ADMIN_USER value in the HELIX_ONPREM_DEPLOYMENT pipeline does not match the value found in the Helix Platform rsso-admin-tas secret.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Set value of RSSO_ADMIN_USER in the HELIX_ONPREM_DEPLOYMENT pipeline to that used in the Helix Platform.\"
  },
  {
    \"id\": \"157\",
    \"cause\": \"The value of HELIX_PLATFORM_NAMESPACE in the HELIX_ONPREM_DEPLOYMENT pipeline is not the name of the Helix Platform namespace.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Correct the value of HELIX_PLATFORM_NAMESPACE and set it to the name of the Helix Platform namespace.\"
  },
  {
    \"id\": \"158\",
    \"cause\": \"The HELIX_PLATFORM_CUSTOMER_NAME value in the HELIX_ONPREM_DEPLOYMENT pipeline must be the same as the TENANT_NAME/COMPANY_NAME in the Helix Platform infra.config file.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Change the HELIX_PLATFORM_CUSTOMER_NAME value in the HELIX_ONPREM_DEPLOYMENT pipeline to that of the Helix Platform TENANT_NAME/COMPANY_NAME.\"
  },
  {
    \"id\": \"159\",
    \"cause\": \"The cacerts secret required by the Helix Service Management applications is missing from the Helix IS namespace.\",
    \"impact\": \"Helix Service Management applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation.\"
  },
  {
    \"id\": \"160\",
    \"cause\": \"The cacerts secret in the Helix Service Management namespace does not contain the Java keystore in a file named 'cacerts'.\",
    \"impact\": \"Helix Service Management applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation and ensure that the Java keystore file is named 'cacerts'.\"
  },
  {
    \"id\": \"161\",
    \"cause\": \"The cacerts file in the cacerts secret in the Helix Service Management namespace must be a Java keystore and not any other type of certificate file.\",
    \"impact\": \"Helix Service Management applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation and ensure that the cacerts file is a Java keystore.\"
  },
  {
    \"id\": \"162\",
    \"cause\": \"The cacerts file in the cacerts secret in the Helix Service Management namespace must contain the certificate used to the access the FTS Elasticsearch system.\",
    \"impact\": \"The Helix Service Management platform pods will not be able to start and the applications will not be accessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation.\"
  },
  {
    \"id\": \"163\",
    \"cause\": \"The cacerts file in the cacerts secret in the Helix Service Management namespace must contain the certificate chain that allows access to the Helix Platform applications such as RSSO.\",
    \"impact\": \"The Helix Service Management applications will not be accessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation and ensure the Helix Platform certificate chain is included.\"
  },
  {
    \"id\": \"164\",
    \"cause\": \"The certificate chain required to validate the connection to the named alias are is present in the cacerts file used for the Helix Service Management deployment.\",
    \"impact\": \"The Helix Service Management applications accessed via the alias will not be accessible.\",
    \"remediation\": \"Recreate the cacerts secret using the process detailed in the product documentation and ensure the required certificate chain is included.\"
  },
  {
    \"id\": \"165\",
    \"cause\": \"The IP address entered as the FTS_ELASTICSEARCH_HOSTNAME has not been found as an externalIP for any service in the Helix Platform namespace.\",
    \"impact\": \"The Helix Service Management platform pods will not be able to start and the applications will not be accessible.\",
    \"remediation\": \"Verify that the correct IP address has been used and that the service is exposed, or use the recommended service.namespace format for the value.\"
  },
  {
    \"id\": \"166\",
    \"cause\": \"The IP address entered for the FTS_ELASTICSEARCH_HOSTNAME does not appear to connect to the expected Elasticsearch system in the Helix Platform.\",
    \"impact\": \"The Helix Service Management platform pods will not be able to start and the applications will not be accessible.\",
    \"remediation\": \"Verify that the correct IP address has been entered or use the recommended service.namespace format for the value.\"
  },
  {
    \"id\": \"167\",
    \"cause\": \"The value entered for the FTS_ELASTICSEARCH_HOSTNAME does not appear to connect to the expected Elasticsearch system.\",
    \"impact\": \"The Helix Service Management platform pods will not be able to start and the applications will not be accessible.\",
    \"remediation\": \"Verify that the correct IP address has been entered or use the recommended service.namespace format for the value.\"
  },
  {
    \"id\": \"168\",
    \"cause\": \"The value entered for the FTS_ELASTICSEARCH_HOSTNAME is not the expected service.namespace indicated in the message.\",
    \"impact\": \"The Helix Service Management platform pods will not be able to start and the applications will not be accessible.\",
    \"remediation\": \"Update the FTS_ELASTICSEARCH_HOSTNAME value to the correct value.\"
  },
  {
    \"id\": \"169\",
    \"cause\": \"The IP address entered for the reported parameter has not been found as an externalIP for any service in the Helix Platform namespace.\",
    \"impact\": \"The Helix Service Management platform pods may not be able to start and the applications may not be accessible.\",
    \"remediation\": \"Verify that the correct IP address has been used and that the service is exposed, or use the recommended service.namespace format for the value.\"
  },
  {
    \"id\": \"170\",
    \"cause\": \"An attempt to validate that the IP address provided connects to an Elasticsearch server did not return the expected results.\",
    \"impact\": \"The Helix Service Management platform pods may not be able to start and the applications may not be accessible.\",
    \"remediation\": \"Verify that the correct IP address has been used and that the Elasticsearch service is running.\"
  },
  {
    \"id\": \"171\",
    \"cause\": \"The Jenkins global pipeline library configuration named in the message does not have the correct value for the 'Load implicitly' option.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins browse to Manage Jenkins -> System, find the pipeline library and set the 'Load implicitly' option as detailed in the message.\"
  },
  {
    \"id\": \"172\",
    \"cause\": \"The value entered for the LOGS_ELASTICSEARCH_HOSTNAME is not the expected service.namespace indicated in the message.\",
    \"impact\": \"Helix Service Management logs will not be sent to Helix Logging.\",
    \"remediation\": \"Update the LOGS_ELASTICSEARCH_HOSTNAME value to the correct value.\"
  },
  {
    \"id\": \"173\",
    \"cause\": \"The FTS_ELASTICSEARCH_PORT must be 9200.\",
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be accessible.\",
    \"remediation\": \"Set the value to 9200.\"
  },
  {
    \"id\": \"174\",
    \"cause\": \"The FTS_ELASTICSEARCH_SECURE option must be selected.\",
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be accessible.\",
    \"remediation\": \"Select the value.\"
  },
  {
    \"id\": \"175\",
    \"cause\": \"The FTS_ELASTICSEARCH_USER_PASSWORD value does not match the value set in the Helix Platform.\",
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be accessible.\",
    \"remediation\": \"Set the value to the correct password.\"
  },
  {
    \"id\": \"176\",
    \"cause\": \"An attempt to login to the Helix Service Management apps via the RESTAPI failed and so the server license could not be checked.\",
    \"impact\": \"License validation has not been possible and some later checks will be skipped.\",
    \"remediation\": \"Check that the hannah_admin user is enabled and that the correct password is stored in the atriumwebsvc secret.\"
  },
  {
    \"id\": \"177\",
    \"cause\": \"The fpackager sidecar containers used by the Support Assistant Tool to access pod logs have not been found.\",
    \"impact\": \"The Support Assistant Tool will not be able to access application logs.\",
    \"remediation\": \"Select the SIDECAR_SUPPORT_ASSISTANT_FPACK option to enable during deployment or when running the HELIX_ONPREM_DEPLOYMENT pipeline in service mode.\"
  },
  {
    \"id\": \"178\",
    \"cause\": \"The role or rolebinding reported in the message has not been found in the Helix Service Management namespace.\",
    \"impact\": \"The Support Assistant Tool will not be able to access application logs.\",
    \"remediation\": \"Use the SUPPORT_ASSISTANT_CREATE_ROLE option in the HELIX_ONPREM_DEPLOYMENT pipeline or follow the steps in the product documentation to create the role/rolebinding manually.\"
  },
  {
    \"id\": \"179\",
    \"cause\": \"The Jenkins global pipeline library configuration named in the message does not have the correct value for the 'Retrieval method' option.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins browse to Manage Jenkins -> System, find the pipeline library and set the 'Retrieval method' to 'Modern SCM'.\"
  },
  {
    \"id\": \"180\",
    \"cause\": \"An attempt to connect to the database using the pipeline values failed. Additional error details may have been included in the main HITT output.\",
    \"impact\": \"Later database checks will not be run and deployment may fail if there is an issue with the database of pipeline values.\",
    \"remediation\": \"Use the additional error details to make changes to resolve the issue.\"
  },
  {
    \"id\": \"181\",
    \"cause\": \"Different versions of the Helix Service Management database are identified using the currDBVersion value in the control table. The discovered value is not the expected one for this version of Helix Service Management.\",
    \"impact\": \"Helix Service Management deployment will fail or the server will not start.\",
    \"remediation\": \"If this is a fresh install verify that the correct database dump was restored. If this is an upgrade issue please contact BMC Support.\"
  },
  {
    \"id\": \"182\",
    \"cause\": \"When using an MSSQL database for the Helix Service Management applications it is required to create several synonyms but the one named in the error is missing.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Create the missing synonym as detailed in the product documentation.\"
  },
  {
    \"id\": \"183\",
    \"cause\": \"The Jenkins credentials object named in the message has a blank password value when it should be set to the password of the named user.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Credentials and update the credential to add the muissing password.\"
  },
  {
    \"id\": \"184\",
    \"cause\": \"The HITT script makes extensive use of the kubectl command but was not able to run it successfully.\",
    \"impact\": \"The HITT script cannot continue without a working kubectl.\",
    \"remediation\": \"Make sure that kubectl works as expected for the git user and that commands such as 'kubectl version' return results.\"
  },
  {
    \"id\": \"185\",
    \"cause\": \"A KUBECONFIG environment variable is set and references a non-default file.  Commands run by the pipelines during deployment may not inherit this environment variable and will not work as expected.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Copy a valid kubeconfig file to the location reported in the error message.\"
  },
  {
    \"id\": \"186\",
    \"cause\": \"Commands run during the Helix Service Management deployment require a valid kubeconfig file in ~/.kube/config but this was not found.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Copy a valid kubeconfig file to the location reported in the error message.\"
  },
  {
    \"id\": \"187\",
    \"cause\": \"A 'kubectl get secret' command failed to return the expected results.\",
    \"impact\": \"Some later checks will not run and deployment may fail.\",
    \"remediation\": \"Run the 'kubectl get secret' command for the secret and namespace in the error message and resolve any issues reported.\"
  },
  {
    \"id\": \"188\",
    \"cause\": \"An attempt to ping the IS database server from a pod failed to return the expected results.  More details may be included in the main HITT output.\",
    \"impact\": \"The cluster to IS database server latency has not been tested.\",
    \"remediation\": \"This test may fail due to security restrictions in the cluster and is for information only.\"
  },
  {
    \"id\": \"189\",
    \"cause\": \"A 'kubectl get secret' command failed to return the expected results.\",
    \"impact\": \"Some later checks will not be run.\",
    \"remediation\": \"Run the 'kubectl get secret' command for the secret and namespace in the error message and resolve any issues reported.\"
  },
  {
    \"id\": \"190\",
    \"cause\": \"The registry server parameter reported in the error message does not match what is currently set in the registry secret in the Helix IS namespace.\",
    \"impact\": \"The pipeline operation may fail.\",
    \"remediation\": \"Verify the value with that in the secret.\"
  },
  {
    \"id\": \"191\",
    \"cause\": \"The Jenkins pipeline parameter named in the message includes a dollar symbol which will lead to parsing errors.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Update the value of the named parameter and remove the dollar symbol.\"
  },
  {
    \"id\": \"192\",
    \"cause\": \"The HITT script attempted a 'docker login' to the registry server using the credentials in the IMAGESECRET_NAME secret but failed.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Verify that the IMAGESECRET_NAME secret in the Helix Service Management namespace contains valid credentials.\"
  },
  {
    \"id\": \"193\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT process uses several Jenkins nodes to perform product installation but one, or more, of these is not available.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Nodes and enable the offline node(s). This may indicate an ssh or git credentials password issue. See the product documentation for full details.\"
  },
  {
    \"id\": \"194\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT process requires a Jenkins node with the label 'ansible-master' to perform the product installation but one was not found.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Nodes and ensure that there is a node with this label. This is usually the node named after the Deployment Engine hostname. See the product documentation for full details.\"
  },
  {
    \"id\": \"195\",
    \"cause\": \"The named plugin is required but missing from Jenkins.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Plugins -> Available Plugins and install the missing plugin.\"
  },
  {
    \"id\": \"196\",
    \"cause\": \"The named credentials item is required but missing from Jenkins.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Credentials and create the missing item. See the product documentation for full details.\"
  },
  {
    \"id\": \"197\",
    \"cause\": \"A command to validate the KUBECONFIG credential in Jenkins failed. The credentials item is expected to contain a valid kubeconfig file but it is missing or is not valid for the cluster.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Credentials and update the KUBECONFIG credential with a valid file. See the product documentation for full details.\"
  },
  {
    \"id\": \"198\",
    \"cause\": \"Several different credentials objects must exist in Jenkins before the HELIX_ONPREM_DEPLOYMENT pipeline can be used to deploy the products but one, or more, are missing.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Credentials and add the missing items. See the product documentation for full details.\"
  },
  {
    \"id\": \"199\",
    \"cause\": \"The command list namespaces in the cluster did not return the expected results needed to provide a list to select from.\",
    \"impact\": \"HITT cannot run until the hitt.conf file is updated.\",
    \"remediation\": \"Update the hitt.conf file and set the namespace names.\"
  },
  {
    \"id\": \"200\",
    \"cause\": \"You must specify the mode to use when running HITT.\",
    \"impact\": \"HITT requires a mode to run.\",
    \"remediation\": \"Specify the mode on the command line.\"
  },
  {
    \"id\": \"201\",
    \"cause\": \"The Helix Platform and Helix IS namespaces are set to the same value in the hitt.conf file.\",
    \"impact\": \"Helix Platform and Helix IS should be installed in separate namespaces.\",
    \"remediation\": \"Update the namespaces in the hitt.conf file.\"
  },
  {
    \"id\": \"202\",
    \"cause\": \"HITT failed to find an existing job to provide the tctl client image name.\",
    \"impact\": \"Some later checks will not be run.\",
    \"remediation\": \"No workaround available.\"
  },
  {
    \"id\": \"203\",
    \"cause\": \"HITT failed to find the name of the container image that provides the tctl client.\",
    \"impact\": \"Some later checks will not be run.\",
    \"remediation\": \"No workaround available.\"
  },
  {
    \"id\": \"204\",
    \"cause\": \"The job used to run tctl commands did not complete in the expected time for some reason.\",
    \"impact\": \"Some later checks will not be run.\",
    \"remediation\": \"Check the tctlseal job/pod events and logs to understand and resolve the issue.\"
  },
  {
    \"id\": \"205\",
    \"cause\": \"BMC_HELIX_ITSM_INSIGHTS is selected to integrate with the Helix Platform but ITSM Insights is not installed in the Helix Platform.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Deselect BMC_HELIX_ITSM_INSIGHTS or install ITSM Insights in the Helix Platform before deployment of Helix Service Management.\"
  },
  {
    \"id\": \"206\",
    \"cause\": \"When using HITT's tctl mode you must remember to enclose the command options in double quotes as in the message.\",
    \"impact\": \"HITT will not run the tctl command.\",
    \"remediation\": \"Enclose the tctl commands in double quotes.\"
  },
  {
    \"id\": \"207\",
    \"cause\": \"The Java version used by HITT is older than that required to use the jenkins-cli.jar command line client.\",
    \"impact\": \"Checks that use the jenkins-cli client will fail.\",
    \"remediation\": \"Update the Java used by HITT to the version indicated in the error message.\"
  },
  {
    \"id\": \"208\",
    \"cause\": \"The currently installed version of ansible is not supported for this release of the Helix Service Management deployment pipelines.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Review the product documentation and install the supported version of ansible.\"
  },
  {
    \"id\": \"209\",
    \"cause\": \"The 'jmespath' module required by the Helix Service Management deployment scripts does not appear to be installed for the python version that ansible is using.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Install 'jmespath' for the python instance that Jenkins is using.\"
  },
  {
    \"id\": \"210\",
    \"cause\": \"The ansible configuration file should have been updated by the Deployment Engine setup script but it is missing, or does not contain the expected settings.\",
    \"impact\": \"Helix Service Management deployment may fail.\",
    \"remediation\": \"Verify that the setup script ran as expected or contact BMC Support for further details.\"
  },
  {
    \"id\": \"211\",
    \"cause\": \"This values should be the ID of a Jenkins credentials object containing the OS user/password used by the pipeline to access the git repository files.\",
    \"impact\": \"The HELIX_ONPREM_DEPLOYMENT pipeline will fail.\",
    \"remediation\": \"Set the value to the correct credentials ID - usually 'github'.\"
  },
  {
    \"id\": \"212\",
    \"cause\": \"The SMARTREPORTING_DB_PASSWORD value in the HELIX_ONPREM_DEPLOYMENT pipeline is too long, it must be 28 characters or less.\",
    \"impact\": \"The HELIX_SMARTREPORTING_DEPLOY pipeline will fail.\",
    \"remediation\": \"Change the SMARTREPORTING_DB_PASSWORD to one that is 28 characters or less.\"
  },
  {
    \"id\": \"213\",
    \"cause\": \"The DEPLOYMENT_MODE is UPGRADE or UPDATE but the SOURCE_VERSION or PLATFORM_HELM_VERSION are invalid for the chosen mode.\",
    \"impact\": \"The UPGRADE/UPDATE will fail.\",
    \"remediation\": \"Review the product documentation and verify the DEPLOYMENT_MODE, SOURCE_VERSION and PLATFORM_HELM_VERSION values.\"
  },
  {
    \"id\": \"214\",
    \"cause\": \"The password entered for CACERTS_SSL_TRUSTSTORE_PASSWORD is not valid for the cacerts file attached to the pipeline or stored in the cacerts secret.\",
    \"impact\": \"Platform pods will be unable to start.\",
    \"remediation\": \"Set CACERTS_SSL_TRUSTSTORE_PASSWORD to the correct password or leave it blank to use the default.\"
  }
]"

while getopts "ce:f:lm:t:" options; do
  case "${options}" in
    c)
      SKIP_CLEANUP=1
      ;;
    e)
      STOP_ON_ERROR="${OPTARG}"
      ;;
    m)
      MODE=${OPTARG}
      ;;
    l)
      CREATE_LOGS=0
      ;;
    t)
      TCTL_CMD=${OPTARG}
      if [ $# -ne 2 ]; then
        logError "206" "tctl commands must be enclosed in double quotes - eg hitt.sh -t \"get tenant\"" 1
      fi
      ;;
    f)
      HITT_CONFIG_FILE=${OPTARG}
      ;;
    :)
      echo -e "${BOLD}ERROR:${NORMAL} -${OPTARG} requires an argument."
      usage
      ;;
    *)
      usage
      ;;
  esac
done

# Call main()
if [ ${CREATE_LOGS} -eq 1 ]; then
  main | tee "${HITT_LOG_FILE}"
else
  main
fi
