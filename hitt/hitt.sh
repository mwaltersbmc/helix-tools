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
  logStatus "Please enter your Jenkins usernamne and password if required, otherwise just press return:"
  read -p "Username : " JENKINS_USERNAME
  read -s -p "Password : " JENKINS_PASSWORD
}

createHITTconf() {
  cat << EOF > "${HITT_CONFIG_FILE}"
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
JENKINS_PORT=8080

# Required Tools - set full path to binary if not already present on path
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
EOF
}

logError() {
  # Print error message / exit if value of 1 passed as second parameter
  MSG="${BOLD}${RED}ERROR${NORMAL} - ${1}"
  echo -e "${MSG}"
  [[ ${2} == 1 ]] && exit 1
  ((FAIL++))
  ERROR_ARRAY+=(" - ${1}")
}

logWarning() {
  # Print warning message
  MSG="${BOLD}${YELLOW}WARNING${NORMAL} - ${1}"
  echo -e "${MSG}"
  ((WARN++))
  WARN_ARRAY+=(" - ${1}")
}

logMessage() {
  # Print message
  echo -e "\t${1}"
}

usage() {
    echo ""
    echo "${BOLD}Helix IS Triage Tool (HITT)${NORMAL}"
    echo "${BOLD}Usage: bash $0 -m <post-hp|pre-is|post-is> [-f HITT_CONFIG_FILE]${NORMAL}"
    echo ""
    echo "Examples:"
    echo "bash $0 -m post-hp   - run post HP installation only checks"
    echo "OR"
    echo "bash $0 -m pre-is   - run pre-installation checks"
    echo "OR"
    echo "bash $0 -m post-is  - run post-installation checks"
    echo ""
    echo "Use ${BOLD}post-hp${NORMAL} after successfully installing the Helix Platform but before using Jenkins."
    echo "Use ${BOLD}pre-is${NORMAL} after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS."
    echo "Use ${BOLD}post-is${NORMAL} for troubleshooting after IS deployment."
    echo "Optional -f to use a different config file."
    exit 1
}

checkVars() {
  if [ -z "${HP_NAMESPACE}" ] || [ -z "${IS_NAMESPACE}" ] || [ -z "${IS_CUSTOMER_SERVICE}" ] || [ -z "${IS_ENVIRONMENT}" ] ; then
    logError "Please set the namespace and IS variables in the ${HITT_CONFIG_FILE} file." 1
  fi
}

checkRequiredTools() {
  for i in "${REQUIRED_TOOLS[@]}"; do
    checkBinary "${i}"
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
      if compare "$INSTALLED_VERSION < $REQUIRED_VERSION"; then
        logError "jq version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed.  Please upgrade from https://jqlang.github.io/jq/download"
        FAIL=1
      fi
      ;;
    *)
    ;;
  esac
}

checkBinary() {
  if ! which "${1}" > /dev/null 2>&1 ; then
    logError "${1} command not found in path. Please set ${1^^}_BIN variable with the full path to the file."
  else
    logMessage "${1} command found ($(which ${1}))."
    checkToolVersion "${1}"
  fi
}

cleanUp() {
  for i in sealcacerts sealstore.p12 sealstore.pem; do
    [[ -f ${i} ]] &&  rm -f ${i}
  done
  for i in configsrepo; do
    [[ -d ${i} ]] &&  rm -rf ${i}
  done
}

generateRandom() {
  STRING=""
  for i in {0..7}; do
    STRING+=$(printf "%x" $(($RANDOM%16)) );
  done
  echo "${STRING}"
}

checkNamespaceExists() {
  # namespace_name - exit if not found
  if ! ${KUBECTL_BIN} get ns "${1}" > /dev/null 2>&1 ; then
    logError "${NS_TYPE} namespace ${1} not found." 1
  else
    logMessage "${NS_TYPE} namespace ${1} found."
  fi
}

checkHPNamespace() {
  # namespace_name
  DEPLOYMENT=rsso
  NS_TYPE="Helix Platform"
  checkNamespaceExists "${1}"
  if ! ${KUBECTL_BIN} -n "${1}" get deployment "${DEPLOYMENT}" > /dev/null 2>&1 ; then
    logError "Deployment ${DEPLOYMENT} not found in ${1} - please check the ${NS_TYPE} namespace name." 1
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
      logError "Registry secret not found in ${1} namespace - HELIX_GENERATE_CONFIG pipeline must have been run before ${MODE} checks." 1
    fi
  fi
  if [ "${MODE}" == "post-is" ]; then
    if ! ${KUBECTL_BIN} -n "${1}" get deployment "${DEPLOYMENT}" > /dev/null 2>&1 ; then
      logError "Deployment ${DEPLOYMENT} not found in ${1} - please check the ${NS_TYPE} namespace name." 1
    fi
  fi
  logMessage "${1} appears to be a valid ${NS_TYPE} namespace."
  checkPodStatus "${1}"
}

checkPodStatus() {
  if [ $(${KUBECTL_BIN} -n "${1}"  get pods -o custom-columns=":metadata.name,:status.containerStatuses[*].state.waiting.reason" | grep -v "<none>" | wc -l) != "1" ]; then
     logError "one or more pods in namespace ${1} found in a non-ready state."
     ${KUBECTL_BIN} -n "${1}" get pods -o custom-columns="POD:metadata.name,STATE:status.containerStatuses[*].state.waiting.reason" | grep -v "<none>"
  else
    logMessage "No unheathly pods found in ${1} namespace."
  fi
}

getVersions() {
  HP_VERSION=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm helix-on-prem-config -o jsonpath='{.data.version}' | head -1)
  EFK_ELASTIC_SERVICENAME="efk-elasticsearch-data-hl"
  logMessage "Helix Platform version - ${HP_VERSION}."
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
        IS_DB_VERSION=201
        ;;
      *)
        logError "Unknown Helix IS version (${IS_VERSION}) - check for script updates." 1
    esac
  fi

  # Set service name for FTS ELasticservice based on HP version
  case "${HP_VERSION%%.*}" in
    22 | 23)
      FTS_ELASTIC_SERVICENAME=elasticsearch-logs-opendistro-es-data-svc
      FTS_ELASTIC_POD=elasticsearch-logs-opendistro-es-data-0
      ;;
    *)
      FTS_ELASTIC_SERVICENAME=opensearch-logs-data
      FTS_ELASTIC_POD=opensearch-logs-data-0
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
    [[ "${ADE_CS_OK}" == "0" ]] && logError "Helix Plaform credential service is not installed or disabled in the TMS deployment.  Please see the 'Known and corrected issues' documentation."
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
  else
    logError "Unable to get RSSO admin token. RSSO response: ${RSSO_TOKEN_JSON}" 1
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
      logWarning "ENABLE_LOG_SHIPPER_IN_PODS=true - consider installing Helix Logging to minimize error messages in Helix Plaform pod logs."
    fi
  fi
}

checkEFKClusterHealth() {
  EFK_ELASTIC_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" -- sh -c 'curl -sk -u elastic:"'"${HELIX_LOGGING_PASSWORD}"'" -X GET https://"'"${EFK_ELASTIC_SERVICENAME}"'":9200/_cluster/health')
  EFK_ELASTIC_STATUS=$(echo "${EFK_ELASTIC_JSON}" | ${JQ_BIN} -r '.status')
  if ! echo "${EFK_ELASTIC_STATUS}" | grep -q green ; then
    logError "Helix Logging Elasticsearch problem - ${EFK_ELASTIC_STATUS} - check ${EFK_ELASTIC_SERVICENAME} pods in Helix Platform namespace."
  else
    logMessage "Helix Logging Elasticsearch (${EFK_ELASTIC_SERVICENAME}) appears healthy."
  fi
}

getTenantDetails() {
  TENANT_JSON=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/tenant -H "Authorization: RSSO ${RSSO_TOKEN}" | ${JQ_BIN} .tenants)
  TENANT_ARRAY=($(echo "${TENANT_JSON}" | ${JQ_BIN} -r .[].name | grep -v SAAS_TENANT))
  if [ "${#TENANT_ARRAY[@]}" == "0" ]; then
    logError "Failed to get tenant(s) from SSO." 1
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
  logMessage "Helix portal hostname is ${PORTAL_HOSTNAME}."
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
    logError "tctl job failed." 1
  fi
  TCTL_OUTPUT=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" logs job/${SEALTCTL} | sed -n -e '/^NAME/,$p' | tail -n +2)
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
    logError "Unable to find job with TCTL image details."
    return 1
  fi
  TCTL_IMAGE=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get job "${TCTL_JOB_NAME}" -o jsonpath='{.spec.template.spec.containers[0].image}')
  if [ -z "${TCTL_IMAGE}" ]; then
    logError "Unable to get TCTL image name from job ${TCTL_JOB_NAME}."
    return 1
  fi
  logMessage "Deploying job ${SEALTCTL} and waiting for it to complete..."
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
          value: get ${TCTL_COMMAND}
        image: ${TCTL_IMAGE}
        imagePullPolicy: IfNotPresent
        name: ${SEALTCTL}
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
  if ! ${KUBECTL_BIN} -n "${HP_NAMESPACE}" wait --for=condition=complete job/"${SEALTCTL}" > /dev/null 2>&1; then
    logError "timed out waiting for job ${SEALTCTL} to complete."
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
    logError "Realm ${REALM_NAME} not found for SAAS_TENANT in RSSO.  Check IS_CUSTOMER_SERVICE and IS_ENVIRONMENT values." 1
  else
    logMessage "RSSO realm ${REALM_NAME} found for the SAAS_TENANT."
  fi
}

checkTenantRealms() {
  TENANT_REALM=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}" -H "X-RSSO-TENANT-IMP: ${PORTAL_HOSTNAME}")
  if ! echo "${TENANT_REALM}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    logError "Helix IS realm (${REALM_NAME}) exists for tenant ${HP_TENANT} when it should be configured for the SAAS_TENANT."
  else
    logMessage "Verified Helix IS realm (${REALM_NAME}) is not configured for tenant ${HP_TENANT}."
  fi
}

validateRealm() {
  # Parse realm data
  REALM_ARHOST=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arHost)
  if [ "${REALM_ARHOST}" != "platform-user-ext.${IS_NAMESPACE}" ]; then
    logError "Invalid arHost in realm - expected platform-user-ext.${IS_NAMESPACE} but found ${REALM_ARHOST}."
  else
    logMessage "AR host ${REALM_ARHOST} is the expected value."
  fi
  REALM_ARPORT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arPort)
  if [ "${REALM_ARPORT}" != "46262" ]; then
    logError "Invalid arPort in realm - expected 46262 but found ${REALM_ARPORT}."
  else
    logMessage "AR port ${REALM_ARPORT} is the expected value."
  fi
  REALM_TENANT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .tenantDomain)
  if [ "${REALM_TENANT}" != "${HP_TENANT}" ]; then
    logError "Invalid TENANT in realm - expected ${HP_TENANT} but found ${REALM_TENANT}."
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
  logMessage "Checking for expected hostname aliases in realm Application Domains list..."
  # Special case when IS_ENVIRONMENT is "prod"
  if [ "${IS_ENVIRONMENT}" == "prod" ]; then
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}"
    logMessage "ENVIRONMENT value is prod - IS hostnames prefix will be \"${IS_ALIAS_PREFIX}-\""
  else
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
    logMessage "IS hostnames prefix is \"${IS_ALIAS_PREFIX}\""
  fi
  # Check for midtier alias
  if ! echo "${REALM_DOMAINS[@]}" | grep -q "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN}" ; then
    logError "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN} not found in Application Domains."
    BAD_DOMAINS=1
  else
    logMessage "${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN} found."
  fi
  # Check for other IS aliases
  for i in "${IS_ALIAS_SUFFIXES[@]}"; do
    TARGET="${IS_ALIAS_PREFIX}-${i}.${CLUSTER_DOMAIN}"
    if ! echo "${REALM_DOMAINS[@]}" | grep -q "${TARGET}" ; then
      logError "${TARGET} not found in Application Domains."
      BAD_DOMAINS=1
    else
      logMessage "${TARGET}.${CLUSTER_DOMAIN} found."
    fi
  done
  # Check for portal alias - will not be present if INTEROPS pipeline has not been run
  if ! echo "${REALM_DOMAINS[@]}" | grep -q "${PORTAL_HOSTNAME}" ; then
    logWarning "${PORTAL_HOSTNAME} not found in Application Domains. This is expected until the HELIX_ITSM_INTEROPS pipeline has been run."
  fi
}

checkServiceDetails() {
  deleteTCTLJob
  if ! deployTCTL service; then
    logError "Failed to get Helix Platform ARSERVICES status."
    return
  fi
  getTCTLOutput
  if ! echo "${TCTL_OUTPUT}" | grep -q "^ITSM "  ; then
    logError "ITSM services not found in Helix Platform - please check that ARSERVICES=yes is set in your infra.config file."
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
  FTS_ELASTIC_STATUS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" -- sh -c 'curl -sk -u admin:admin -X GET https://localhost:9200/_cluster/health?pretty | grep status')
  if ! echo "${FTS_ELASTIC_STATUS}" | grep -q green ; then
    logError "FTS Elasticsearch problem - ${FTS_ELASTIC_STATUS} - check ${FTS_ELASTIC_SERVICENAME} pods in Helix Platform namespace."
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
  IS_FTS_ELASTICSEARCH_USERNAME=$(getValueFromPlatformSecret "FTS_ELASTIC_SEARCH_USERNAME")
  IS_FTS_ELASTICSEARCH_USER_PASSWORD=$(getValueFromPlatformSecret "FTS_ELASTIC_SEARCH_USER_PASSWORD")
  IS_AR_DB_USER=$(getValueFromPlatformSecret "AR_SERVER_DB_USERNAME")

  IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_PLATFORM_SECRET}" | ${JQ_BIN} -r '.CACERTS_SSL_TRUSTSTORE_PASSWORD')
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" != "null" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" | ${BASE64_BIN} -d)
  else
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi

  IS_ENABLE_PLATFORM_INT_NORMALIZATION="false"
  IS_PLATFORM_INT=0
  if [ $(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get pod -l app=platform-int > /dev/null 2>&1 | wc -l) != "0" ]; then
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
  if ! "${CURL_BIN}" -s "http://${JENKINS_HOSTNAME}:${JENKINS_PORT}/whoAmI/api/json?tree=authenticated" | grep -q WhoAmI ; then
    logError "Jenkins not found on http://${JENKINS_HOSTNAME}:${JENKINS_PORT} - skipping Jenkins tests."
    SKIP_JENKINS=1
  else
    JENKINS_RESPONSE=$(${CURL_BIN} -sI "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}")
    JENKINS_VERSION=$(echo "${JENKINS_RESPONSE}" | grep -i 'X-Jenkins:' | awk '{print $2}' | tr -d '\r')
    JENKINS_HTTP_CODE=$(echo "${JENKINS_RESPONSE}" | grep "^HTTP" | cut -f 2 -d ' '| tr -d '\r')
    logMessage "Jenkins version ${JENKINS_VERSION} found on http://${JENKINS_HOSTNAME}:${JENKINS_PORT}"
    if [ "${JENKINS_HTTP_CODE}" != "200" ]; then
      logError "Jenkins authentication is enabled but the credentials in hitt.conf are blank or wrong.  Please set correct credentials in the HITT config file (${HITT_CONFIG_FILE})." 1
      SKIP_JENKINS=1
    fi
fi
}

getISDetailsFromJenkins() {
  [[ "${MODE}" != "pre-is" ]] && return
  checkJenkinsIsRunning
  [[ "${SKIP_JENKINS}" == "1" ]] && return
  checkJenkinsConfig
  logMessage "Reading values from Jenkins..."
  JENKINS_JSON=$(${CURL_BIN} -sk "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/job/HELIX_ONPREM_DEPLOYMENT/lastBuild/api/json")
  checkJenkinsJobResult
  JENKINS_PARAMS=$(echo "${JENKINS_JSON}" | ${JQ_BIN} -r '.actions[] | select(._class=="hudson.model.ParametersAction") .parameters[]')

  getPipelineValues
}

checkJenkinsJobResult() {
  if ! echo "${JENKINS_JSON}" | ${JQ_BIN} -r .result | grep -q "SUCCESS"; then
    logWarning "Last build of HELIX_ONPREM_DEPLOYMENT was not successful. Please review the console output for both this and the HELIX_GENERATE_CONFIG pipelines."
  fi
}

parseJenkinsParam() {
  echo "${JENKINS_PARAMS}" | ${JQ_BIN} -r ' . | select(.name=="'"$1"'") .value'
}

createPipelineVarsArray() {
  PIPELINE_VARS=(
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
    CUSTOMER_SIZE
    HELM_NODE
    HELIX_ITSM_INSIGHTS
    HELIX_BWF
    HELIX_DWP
    HELIX_DWPA
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
    DATABASE_HOST_NAME
    DATABASE_ADMIN_USER
    DATABASE_RESTORE
    LOGS_ELASTICSEARCH_HOSTNAME
    LOGS_ELASTICSEARCH_TLS
    AR_DB_NAME
    AR_DB_USER
    FTS_ELASTICSEARCH_HOSTNAME
    FTS_ELASTICSEARCH_PORT
    FTS_ELASTICSEARCH_SECURE
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
    RSSO_ADMIN_PASSWORD
    PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USER_PASSWORD
    PLATFORM_COMMON_FTS_ELASTIC_SEARCH_USERNAME
    PLATFORM_COMMON_CACERTS_SSL_TRUSTSTORE_PASSWORD
    IMAGE_REGISTRY_PASSWORD
    SIDECAR_FLUENT_PASSWORD
  )
}

getPipelineValues() {
  createPipelineVarsArray
  for i in "${PIPELINE_VARS[@]}"; do
    eval "IS_$i=$(parseJenkinsParam ${i})"
  done

  ISP_CUSTOMER_SERVICE=$(parseJenkinsParam CUSTOMER_SERVICE)
  ISP_ENVIRONMENT=$(parseJenkinsParam ENVIRONMENT)
  if isBlank "${ISP_CUSTOMER_SERVICE}" || isBlank "${ISP_ENVIRONMENT}" ; then
    logError "CUSTOMER_SERVICE and/or ENVIRONMENT are blank - please enter all requried values in the HELIX_ONPREM_DEPLOYMENT pipeline." 1
  fi
  if [ "${IS_CUSTOMER_SIZE}" == "M" ] || [ "${IS_CUSTOMER_SIZE}" == "L" ] || [ "${IS_CUSTOMER_SIZE}" == "XL" ]; then
    IS_PLATFORM_INT=1
  fi
  cloneCustomerConfigsRepo
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
  IS_CACERTS_SSL_TRUSTSTORE_PASSWORD="${PLATFORM_COMMON_CACERTS_SSL_TRUSTSTORE_PASSWORD}"
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
  GIT_REPO_DIR=$(parseJenkinsParam GIT_REPO_DIR)
  INPUT_CONFIG_FILE="configsrepo/customer/${IS_CUSTOMER_SERVICE}/${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}.sh"
  if ! ${GIT_BIN} clone "${GIT_REPO_DIR}"/CUSTOMER_CONFIGS/onprem-remedyserver-config.git configsrepo > /dev/null 2>&1 ; then
    logError "Failed to clone ${GIT_REPO_DIR}/CUSTOMER_CONFIGS/onprem-remedyserver-config.git"
    SKIP_REPO=1
    return
  else
    logMessage "Cloned CUSTOMER_CONFIGS repo to configsrepo directory."
  fi
  if [ ! -f "${INPUT_CONFIG_FILE}" ]; then
    logError "Input config file (${INPUT_CONFIG_FILE}) not found. Has the HELIX_GENERATE_CONFIG pipeline been run successfully?"
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
    logError "Value for ${1:3} is not expected to be blank."
  else
    logMessage "Value set for ${1:3}."
  fi
}

validateISDetails() {
  [[ "${SKIP_JENKINS}" == "1" ]] && return
  # Common to pre and post
  if [ "${IS_TENANT_DOMAIN}" != "${HP_TENANT}" ]; then
    logError "TENANT_DOMAIN (${IS_TENANT_DOMAIN}) does not match the Helix Platform tenant (${HP_TENANT})."
  else
    logMessage "TENANT_DOMAIN is the expected value of ${HP_TENANT}."
  fi

  if [ "${IS_RSSO_URL}" != "${RSSO_URL}" ]; then
    logError "IS RSSO_URL (${IS_RSSO_URL}) does not match the Helix Platform RSSO_URL (${RSSO_URL})."
  else
    logMessage "IS RSSO_URL is the expected value of ${RSSO_URL}."
  fi

  if [ "${#IS_AR_SERVER_APP_SERVICE_PASSWORD}" -gt 19 ]; then
    logError "AR_SERVER_APP_SERVICE_PASSWORD is too long - maximum of 19 characters."
  else
    logMessage "AR_SERVER_APP_SERVICE_PASSWORD length is 19 characters or less."
  fi

  if [ "${#IS_AR_SERVER_DSO_USER_PASSWORD}" -gt 20 ]; then
    logError "AR_SERVER_DSO_USER_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_DSO_USER_PASSWORD length is 20 characters or less."
  fi

  if [ "${#IS_AR_SERVER_MIDTIER_SERVICE_PASSWORD}" -gt 20 ]; then
    logError "AR_SERVER_MIDTIER_SERVICE_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_MIDTIER_SERVICE_PASSWORD length is 20 characters or less."
  fi

  if [ "${IS_PLATFORM_INT}" == "1" ] ; then
    if [ "${IS_ENABLE_PLATFORM_INT_NORMALIZATION}" == "false" ]; then
      logWarning "platform-int pods are enabled but ENABLE_PLATFORM_INT_NORMALIZATION is not selected."
    fi
  fi

  # PRE mode only
  if [ "${MODE}" == "pre-is" ]; then
    if [ "${IS_CUSTOM_BINARY_PATH}" == "true" ]; then
      logWarning "CUSTOM_BINARY_PATH option is selected - this is not usually required and may be a mistake."
    fi

    if ! ${KUBECTL_BIN} config get-contexts "${IS_CLUSTER}" > /dev/null 2>&1; then
      logError "CLUSTER (${IS_CLUSTER}) is not a valid context in your kubeconfig file. Available contexts are:"
      ${KUBECTL_BIN} config get-contexts
    else
      logMessage "CLUSTER (${IS_CLUSTER}) is a valid kubeconfig context."
    fi

    if [ "${IS_CLOUD}" == "true" ]; then
      logWarning "IS_CLOUD option is selected - this will cause public cloud systems to provision external an load balancer."
    fi

    if [ "${IS_ROUTE_ENABLED}" == "true" ] || [ "${IS_ROUTE_TLS_ENABLED}" == "true" ]; then
      logWarning "ROUTE_ENABLED and/or ROUTE_TLS_ENABLED are selected but should not be."
    fi

    if [ "${IS_IS_NAMESPACE}" != "${IS_NAMESPACE}" ]; then
      logError "Pipeline IS_NAMESPACE (${IS_IS_NAMESPACE}) does not match IS_NAMESPACE defined in this script (${IS_NAMESPACE})."
    else
      logMessage "IS_NAMESPACE is the expected value (${IS_NAMESPACE})."
    fi

    if [ "${#IS_IS_NAMESPACE}" -gt 33 ]; then
      logError "IS_NAMESPACE is too long - maximum of 33 characters."
    else
      logMessage "IS_NAMESPACE length is 33 characters or less."
    fi

    if [ "${ISP_CUSTOMER_SERVICE}-${ISP_ENVIRONMENT}" != "${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}" ]; then
      logError "CUSTOMER_SERVICE (${ISP_CUSTOMER_SERVICE}) or ENVIRONMENT (${ISP_ENVIRONMENT}) do not match values defined in this script (${IS_CUSTOMER_SERVICE} and ${IS_ENVIRONMENT})."
    else
      logMessage "CUSTOMER_SERVICE and ENVIRONMENT appear valid (${ISP_CUSTOMER_SERVICE} / ${ISP_ENVIRONMENT})."
    fi

    if isBlank "${IS_INGRESS_CLASS}" || ! ${KUBECTL_BIN} get ingressclasses.networking.k8s.io "${IS_INGRESS_CLASS}" > /dev/null 2>&1 ; then
      logError "INGRESS_CLASS (${IS_INGRESS_CLASS})is blank or not valid."
    else
      logMessage "INGRESS_CLASS (${IS_INGRESS_CLASS}) appears valid."
    fi

    if [ "${IS_CLUSTER_DOMAIN}" != "${CLUSTER_DOMAIN}" ]; then
      logError "CLUSTER_DOMAIN (${IS_CLUSTER_DOMAIN}) does not match that used for the Helix Platform (${CLUSTER_DOMAIN})."
    else
      logMessage "CLUSTER_DOMAIN has the expected value of ${CLUSTER_DOMAIN}."
    fi

    if [ "${IS_INPUT_CONFIG_METHOD}" != "Generate_Input_File" ]; then
      logError "INPUT_CONFIG_METHOD should be Generate_Input_File."
    else
      logMessage "INPUT_CONFIG_METHOD has the expected value of Generate_Input_File."
    fi

    if isBlank "${IS_HELM_NODE}" ; then
      logError "HELM_NODE is blank."
    else
      NODE_ARRAY=($(${CURL_BIN} -sk "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/computer/api/json" | ${JQ_BIN} -r .computer[].displayName | grep -v Built ))
      NODE_MATCH=0
      for i in "${NODE_ARRAY[@]}"; do
        if [ "${IS_HELM_NODE}" == "${i}" ]; then NODE_MATCH=1; fi
      done
      if [ "${NODE_MATCH}" == 1"" ]; then
        logMessage "HELM_NODE (${IS_HELM_NODE}) is a valid node in Jenkins."
      else
        logError "HELM_NODE (${IS_HELM_NODE}) not found as a Jenkins node.  Available nodes are:"
        printf '%s\n' "${NODE_ARRAY[@]}"
      fi
    fi

    if [ "${ITSM_INSIGHTS}" == "1" ] && ([ "${IS_BMC_HELIX_ITSM_INSIGHTS}" == "true" ] || [ "${IS_HELIX_ITSM_INSIGHTS}" == "true" ]) ; then
        logWarning "BMC_HELIX_ITSM_INSIGHTS and/or HELIX_ITSM_INSIGHTS are selected but ITSM Insights is not installed in the Helix Platform."
    fi

    if [ "${IS_BMC_HELIX_ITSM_INSIGHTS}" == "true" ] && [ "${IS_HELIX_ITSM_INSIGHTS}" == "false" ] ; then
      logWarning "BMC_HELIX_ITSM_INSIGHTS is selected in the INTEROPS section but HELIX_ITSM_INSIGHTS is not selected as a product to install."
    else
      logMessage "INTEROPS BMC_HELIX_ITSM_INSIGHTS and HELIX_ITSM_INSIGHTS product options are consistent."
    fi

    if [ "${IS_SIDECAR_SUPPORT_ASSISTANT_FPACK}" != "true " ]; then
      logWarning "SIDECAR_SUPPORT_ASSISTANT_FPACK not selected - Support Assistant Tool will not be able to access application logs."
    fi
    if [ "${IS_SUPPORT_ASSISTANT_CREATE_ROLE}" != "true " ]; then
      logWarning "SUPPORT_ASSISTANT_CREATE_ROLE not selected - Support Assistant Tool will not be able to access application logs unless the role/rolebinding are manaually created."
    fi

    if [ "${IS_REGISTRY_TYPE}" != "DTR" ]; then
      logError "REGISTRY_TYPE must be DTR."
    else
      logMessage "REGISTRY_TYPE is the expected value of DTR."
    fi

    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${HP_REGISTRY_SERVER}" ]; then
      logError "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) does not match the Helix Platform registry server (${HP_REGISTRY_SERVER})."
    else
      logMessage "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) matches the Helix Platform registry server (${HP_REGISTRY_SERVER})."
    fi

    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${HP_REGISTRY_USERNAME}" ]; then
      logError "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) does not match the Helix Platform registry username (${HP_REGISTRY_USERNAME})."
    else
      logMessage "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) matches the Helix Platform registry username (${HP_REGISTRY_USERNAME})."
    fi

    if [ "${IS_DB_SSL_ENABLED}" == "true" ]; then
        logError "DB_SSL_ENABLED should not be selected."
    fi

    if [ "$HELIX_LOGGING_DEPLOYED" == 0 ]; then
      if [ "${IS_SIDECAR_FLUENTBIT}" == true ]; then
        logWarning "SIDECAR_FLUENTBIT selected but Helix Logging is not installed."
      fi
    fi

    if [ "$HELIX_LOGGING_DEPLOYED" == 1 ]; then
      if [ "${IS_LOGS_ELASTICSEARCH_TLS}" != "true" ]; then
        logError "LOGS_ELASTICSEARCH_TLS (${IS_LOGS_ELASTICSEARCH_TLS}) is not the expected value of true."
      else
        logMessage "LOGS_ELASTICSEARCH_TLS is the expected value of true."
      fi
      if [ "${IS_LOGS_ELASTICSEARCH_PASSWORD}" != "${HELIX_LOGGING_PASSWORD}" ]; then
        logError "LOGS_ELASTICSEARCH_PASSWORD does not match the Helix Platform KIBANA_PASSWORD."
      else
        logMessage "LOGS_ELASTICSEARCH_PASSWORD matches the Helix Platform KIBANA_PASSWORD."
      fi
      checkIsValidElastic "${IS_LOGS_ELASTICSEARCH_HOSTNAME}" "LOGS_ELASTICSEARCH_HOSTNAME"
    fi

#    if [ "${IS_IMAGE_REGISTRY_PASSWORD}" != "${HP_REGISTRY_PASSWORD}" ]; then
#      logError "IMAGE_REGISTRY_PASSWORD does not match the Helix Platform registry password."
#    else
#      logMessage "IMAGE_REGISTRY_PASSWORD matches the Helix Platform registry password."
#    fi

    if [ "$IS_VC_RKM_USER_NAME" == "${IS_VC_PROXY_USER_LOGIN_NAME}" ] || [ -z "$IS_VC_RKM_USER_NAME" ] || [ -z "${IS_VC_PROXY_USER_LOGIN_NAME}" ]; then
      logError "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME must be different and cannot be blank."
    else
      logMessage "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME appear valid."
    fi

    if [ -n "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" ] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ ^\[.* ]] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ .*\]$ ]]; then
      logError "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS (${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}) does not match the expected format of [x.x.x.x] - missing square brackets?"
    else
      logMessage "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS is blank or matches the expected format - (${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS})."
    fi

    if [ "${IS_RSSO_ADMIN_USER,,}" != "${RSSO_USERNAME,,}" ]; then
      logError "RSSO_ADMIN_USER (${IS_RSSO_ADMIN_USER}) does not match the Helix Platform RSSO_ADMIN_USER (${RSSO_USERNAME})."
    else
      logMessage "RSSO_ADMIN_USER is the expected value of ${IS_RSSO_ADMIN_USER}."
    fi

    if [ "${IS_HELIX_PLATFORM_NAMESPACE}" != "${HP_NAMESPACE}" ]; then
      logError "HELIX_PLATFORM_NAMESPACE (${IS_HELIX_PLATFORM_NAMESPACE}) is not the expected value of ${HP_NAMESPACE}."
    else
      logMessage "HELIX_PLATFORM_NAMESPACE is the expected value of ${HP_NAMESPACE}."
    fi

    if [ "${IS_HELIX_PLATFORM_CUSTOMER_NAME}" != "${HP_COMPANY_NAME}" ]; then
      logError "HELIX_PLATFORM_CUSTOMER_NAME (${IS_HELIX_PLATFORM_CUSTOMER_NAME}) is not the expected value of ${HP_COMPANY_NAME}."
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
      logWarning "cacerts file not found - remember to attach when building the HELIX_ONPREM_DEPLOYMENT pipeline unless using a Digicert certificate."
      SKIP_CACERTS=1
    fi
  fi

  if [ "${MODE}" == "post-is" ]; then
    logMessage "Extracting cacerts file from Helix IS cacerts secret..."
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts > /dev/null 2>&1; then
      logError "cacerts secret not found in Helix IS namespace."
      SKIP_CACERTS=1
      return
    fi
    IS_CACERTS_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts -o json)
    IS_CACERTS=$(echo "${IS_CACERTS_JSON}" | ${JQ_BIN} -r '.data.cacerts')
    if [ "${IS_CACERTS}" == "null" ]; then
      logError "Required file 'cacerts' not found in the cacerts secret. File(s) in the secret are:"
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
    logError "cacerts file is of type ${CACERTS_FILETYPE} and not the expected Java keystore."
    return
  else
    logMessage "cacerts file is a valid Java keystore."
  fi

  if ! ${KEYTOOL_BIN} --list -keystore sealcacerts -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -alias esnode > /dev/null 2>&1 ; then
    logError "cacerts file does not contain the expected esnode certificate required for FTS Elasticsearch connection."
  else
    logMessage "cacerts file contains Elasticsearch esnode certificate."
  fi

  # Convert JKS to pem
  logMessage "Processing cacerts..."
  ${KEYTOOL_BIN} -importkeystore -srckeystore sealcacerts -destkeystore sealstore.p12 -srcstoretype jks -deststoretype pkcs12 -srcstorepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -deststorepass changeit > /dev/null 2>&1
  ${OPENSSL_BIN} pkcs12 -in sealstore.p12 -out sealstore.pem -password pass:"${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" > /dev/null 2>&1
  if ! ${CURL_BIN} -s "${RSSO_URL}" --cacert sealstore.pem ; then
    logError "cacerts file does not appear to contain all the certificates required to connect to Helix."
  else
    logMessage "cacerts file appears valid."
  fi
}

checkISFTSElasticHost() {
  # IP/service.ns pipeline_param_name
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "FTS_ELASTICSEARCH_HOSTNAME IP address (${1}) not found as an externalIP for any exposed service in the Helix Platform namespace."
    else
      logWarning "Recommend using servicename.namespace format instead of an exposed IP address for FTS_ELASTICSEARCH_HOSTNAME."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u admin:admin -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "${1} does not appear to be a valid Elasticsearch server IP address."
      else
        if ! echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name' | grep -q 'logs$' ; then
          logError "${1} does not appear to be the expected Elasticsearch service instance for FTS."
          echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name'
        else
          logMessage "${1} appears to be a valid Elasticsearch service instance for FTS."
        fi
      fi
    fi
  else
    if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
      logError "FTS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
    else
      logMessage "FTS_ELASTICSEARCH_HOSTNAME appears valid (${1})."
    fi
  fi
}

checkIsValidElastic() {
  BAD_ELASTIC=0
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "${2} IP address (${1}) not found as an externalIP for any exposed service in the Helix Platform namespace."
      return
    else
      logWarning "Recommend using servicename.namespace format instead of an exposed IP address for ${2}."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u "${3}:${4}" -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "${1} does not appear to be a valid Elasticsearch server IP address."
        return
      fi
    fi
  else
    case "${2}" in
      FTS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
          logError "FTS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
        fi
        ;;
      LOGS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${EFK_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
          logError "LOGS_ELASTICSEARCH_HOSTNAME service name (${1}) is not the expected value of ${EFK_ELASTIC_SERVICENAME}.${HP_NAMESPACE}."
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
    logError "FTS_ELASTICSEARCH_PORT (${IS_FTS_ELASTICSEARCH_PORT}) is not the expected value of 9200."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_PORT is the expected value of 9200."
  fi

  if [ "${IS_FTS_ELASTICSEARCH_SECURE}" != "true" ]; then
    logError "FTS_ELASTICSEARCH_SECURE (${IS_FTS_ELASTICSEARCH_SECURE}) is not the expected value of true."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_SECURE is the expected value of true."
  fi

  if [ "${IS_FTS_ELASTICSEARCH_USERNAME}" != "admin" ]; then
    logError "FTS_ELASTICSEARCH_USERNAME (${IS_FTS_ELASTICSEARCH_USERNAME}) is not the expected value of admin."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_USERNAME is the expected value of admin."
  fi

  if [ -n "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}" ] && [ "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}" != "admin" ]; then
    logError "FTS_ELASTICSEARCH_USER_PASSWORD (${IS_FTS_ELASTICSEARCH_USER_PASSWORD}) is not the expected value."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_USER_PASSWORD is the expected value."
  fi

  [[ "${BAD_FTS_ELASTIC}" == "0" ]] && checkIsValidElastic "${IS_FTS_ELASTICSEARCH_HOSTNAME}" "FTS_ELASTICSEARCH_HOSTNAME" "${IS_FTS_ELASTICSEARCH_USERNAME}" "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}"

}

checkISLicenseStatus() {
  getISAdminCreds
  if ! getISJWT; then
    logError "failed to authenticate user ${IS_ADMIN_USER} - can't check IS license status."
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
    logWarning "IS Server does not have a permanent license - current license type is ${IS_LICENSE_TYPE}."
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
      logError "fpackager sidecar containers not found - Support Assistant will not be able to access application logs."
    else
      logMessage "fpackager sidecar containers are present."
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get role assisttool-rl > /dev/null 2>&1 ; then
      logError "assisttool-rl role not found - Support Assistant will not be able to access application logs."
    else
      logMessage "assisttool-rl role present in Helix IS namespace."
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get rolebinding assisttool-rlb > /dev/null 2>&1 ; then
      logError "assisttool-rlb rolebinding not found - Support Assistant will not be able to access application logs."
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
      JISQLURL=jdbc:oracle:thin:@//${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${IS_AR_DB_NAME}
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
  if ! ${NC_BIN} -z "${1}" "${2}"; then
    return 1
  else
    return 0
fi
}

checkISDBSettings() {
  if ! testNetConnection "${IS_DATABASE_HOST_NAME}" "${IS_DB_PORT}"; then
    logError "IS DB server (${IS_DATABASE_HOST_NAME}) is not reachable on port ${IS_DB_PORT} - skipping DB checks."
    return
  else
    logMessage "IS DB server (${IS_DATABASE_HOST_NAME}) is reachable on port ${IS_DB_PORT}."
  fi
  checkISDBLatency
  if [ -z "${IS_AR_DB_USER}" ] || [ -z "${IS_AR_DB_PASSWORD}" ]; then
    logWarning "One or more DB settings are blank - skipping checks."
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
     logError "problem connnecting to database - please review the following message."
     echo "${SQL_RESULT}"
    else
      DB_VERSION=$(echo "${SQL_RESULT}" | awk '{print $1}')
      if [ ! -z "${IS_DB_VERSION}" ]; then
        if [ "${DB_VERSION}" != "${IS_DB_VERSION}" ]; then
          logError "database is not the expected version - found ${DB_VERSION} but should be ${IS_DB_VERSION}."
        else
          logMessage "Database is the expected version - ${DB_VERSION}."
        fi
      else
        logMessage "Database currDbVersion is ${DB_VERSION}."
      fi
    fi
  else
    logMessage "DB jar files not found - skipping checks.  Download dbjars.tgz to the HITT directory to enable them..."
  fi
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
  if [ $FAIL -gt 0 ] || [ $WARN -gt 0 ] ; then
    echo "${BOLD}${FAIL} errors / ${WARN} warnings found - please review output for details.${NORMAL}"
    if [ "${#ERROR_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${RED}ERRORS:${NORMAL}"
      printf '%s\n' "${ERROR_ARRAY[@]}"
    fi
    if [ "${#WARN_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${YELLOW}WARNINGS:${NORMAL}"
      printf '%s\n' "${WARN_ARRAY[@]}"
    fi
  else
    echo "${BOLD}Tests complete - no errors or warnings found.${NORMAL}"
  fi
}

checkKubeconfig() {
  KUBECONFIG_ERROR=0
  if ! ${KUBECTL_BIN} version > /dev/null 2>&1; then
    logError "'kubectl version' command returned an error - unable to continue." 1
  fi
  if [ ! -z "${KUBECONFIG}" ] && [ "${KUBECONFIG}" != "${HOME}/.kube/config" ]; then
    logError "KUBECONFIG environment variable is set (${KUBECONFIG}) but is not the default of ${HOME}/.kube/config required by Jenkins."
    KUBECONFIG_ERROR=1
  fi
  if [ ! -f ~/.kube/config ]; then
    logError "Default KUBECONFIG file (~/home/.kube/config) required by Jenkins pipelines not found."
    KUBECONFIG_ERROR=1
  fi
  if [ ${KUBECONFIG_ERROR} == "0" ]; then
    logMessage "Local KUBECONFIG file appears valid."
  fi
}

logStatus() {
  echo "${BOLD}${1}${NORMAL}"
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
    logError "couldn't get registry details from ${2} secret in ${1} namespace."
    SKIP_REGISTRY=1
    return
  fi
  REGISTRY_SERVER=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].key')
  REGISTRY_USERNAME=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].value.username')
  REGISTRY_PASSWORD=$(echo "${IMAGESECRET_JSON}" | ${JQ_BIN} -r '.auths | to_entries[].value.password')
}

getRegistryDetailsFromIS() {
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
      logError "Unexpected response from IS DB ping test ${PING_RESULT}."
    fi
  fi
}

checkISDockerLogin() {
  SKIP_REGISTRY=0
  getRegistryDetailsFromIS
  if [ "${SKIP_REGISTRY}" == "1" ]; then
    logError "failed to get IS registry details - skipping checks."
    return
  fi

  if [ "${MODE}" == "pre-is" ]; then
    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${IS_SECRET_HARBOR_REGISTRY_HOST}" ]; then
      logError "HARBOR_REGISTRY_HOST (${IS_HARBOR_REGISTRY_HOST}) does not match the value in the registry secret (${IS_SECRET_HARBOR_REGISTRY_HOST})."
      return
    fi
    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" ]; then
      logError "IMAGE_REGISTRY_USERNAME (${IS_IMAGE_REGISTRY_USERNAME}) does not match the value in the registry secret (${IS_SECRET_IMAGE_REGISTRY_USERNAME})."
      return
    fi
#    if [ "${IS_IMAGE_REGISTRY_PASSWORD}" != "${IS_SECRET_IMAGE_REGISTRY_PASSWORD}" ]; then
#      logError "IMAGE_REGISTRY_PASSWORD does not match the value in the registry secret."
#      return
#    fi
  fi

  if ! docker ps > /dev/null 2>&1; then
    logWarning "'docker' command not found or failed - skipping registry credentials check."
    return
  fi
  if docker login "${IS_SECRET_HARBOR_REGISTRY_HOST}" -u "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" -p "${IS_SECRET_IMAGE_REGISTRY_PASSWORD}" > /dev/null 2>&1 ; then
    logMessage "IMAGE_REGISTRY credentials are valid - docker login to ${IS_SECRET_HARBOR_REGISTRY_HOST} was successful."
  else
    logError "'docker login' to ${IS_SECRET_HARBOR_REGISTRY_HOST} failed - please check credentials."
  fi
}

dumpVARs() {
  [[ "${DUMPVARS}" = "" ]] && return
  # Debug mode to print all variables
  if [ "${MODE}" == "pre-is" ]; then
    logMessage "${BOLD}PIPELINE_VARS...${NORMAL}"
    for i in "${PIPELINE_VARS[@]}"; do
      v="IS_${i}"
      echo "${i}=${!v}"
    done
  fi
  if [ "${MODE}" == "post-is" ]; then
    logMessage "${BOLD}K8S_VARS...${NORMAL}"
    for i in "${PIPELINE_VARS[@]}"; do
      v="IS_${i}"
      if [ "${!v}" != "" ]; then
        echo "${i}=${!v}"
      fi
    done
  fi
}

checkJenkinsConfig() {
  logMessage "Checking expected plugins exist in Jenkins..."
  checkJenkinsPlugins
  logMessage "Checking nodes in Jenkins..."
  checkJenkinsNodes
}

checkJenkinsNodes() {
  NODE_STATUS=$(${CURL_BIN} -s "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/manage/computer/api/json?depth=1")
  OFFLINE_NODES=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[]| select(.offline=='true').displayName')
  if [ ! -z "${OFFLINE_NODES}" ] ; then
    logError "One or more Jenkins nodes found in an 'offline' state."
    printf '%s\n' "${OFFLINE_NODES}"
  fi

  NODE_LABELS=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[].assignedLabels[].name')
  if ! echo "${NODE_LABELS}" | grep -q 'ansible-master' ; then
    logError "No Jenkins nodes found with the 'ansible-master' label."
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
    pipeline-stage-view
    pipeline-rest-api
    )
  JK_PLUGINS=$(${CURL_BIN} -s "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/pluginManager/api/json?depth=1" | ${JQ_BIN} -r '.plugins[].shortName')
  for i in "${EXPECTED_PLUGINS[@]}" ; do
    if ! echo "${JK_PLUGINS}" | grep -wq "${i}" ; then
      logError "Jenkins plugin '${i}' is missing."
    fi
  done
}

checkJenkinsCredentials() {
  # Get list of credentials and check for expected IDs
  EXPECTED_CREDENTIALS=(github ansible_host ansible kubeconfig TOKENS)
   #password_vault_apikey)
  JK_CREDS=$(${CURL_BIN} -s "http://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}/credentials/api/json?depth=3"  | ${JQ_BIN} -r '.stores.system.domains._.credentials[].id')
  for i in "${EXPECTED_CREDENTIALS[@]}" ; do
    if ! echo "${JK_CREDS}" | grep -wq "${i}" ; then
      logError "Jenkins credentials with id '${i}' is missing."
    fi
  done
}
# FUNCTIONS End

# MAIN Start
SCRIPT_VERSION=1
HITT_CONFIG_FILE=hitt.conf
FAIL=0
WARN=0
SKIP_JENKINS=0
REQUIRED_TOOLS=(kubectl curl keytool openssl jq base64 git java tar nc)
IS_ALIAS_SUFFIXES=(smartit sr is restapi atws dwp dwpcatalog vchat chat int)
BOLD=$(tput bold)
NORMAL=$(tput sgr0)
RED="\e[1;31m"
YELLOW="\e[1;33m"
SEALTCTL=sealtctl
KUBECTL_BIN=kubectl
JQ_BIN=jq
ERROR_ARRAY=()
WARN_ARRAY=()
JENKINS_CREDENTIALS=""

while getopts "m:f:" options; do
  case "${options}" in
    m)
      MODE=${OPTARG}
      ;;
    f)
      HITT_CONFIG_FILE=${OPTARG}
      ;;
    :)
      echo "${BOLD}ERROR:${NORMAL} -${OPTARG} requires an argument."
      usage
      ;;
    *)
      usage
      ;;
  esac
done

logStatus "Welcome to the Helix IS Triage Tool."
logStatus "Checking KUBECONFIG file..."
checkKubeconfig

# config file checks
if [ ! -f "${HITT_CONFIG_FILE}" ]; then
  if ! ${KUBECTL_BIN} get ns > /dev/null 2>&1 ; then
    createHITTconf
    logError "'kubectl get namespaces' command returned unexpected results - please update the HITT config file (${HITT_CONFIG_FILE}) manually." 1
  fi
  NS_ARRAY=($(${KUBECTL_BIN} get ns --no-headers -o custom-columns=':.metadata.name'))
  logStatus "HITT config file (${HITT_CONFIG_FILE}) not found - creating..."
  logStatus "Please use the following steps to configure the HITT and create your config file..."
  getConfValues
  createHITTconf
fi
source "${HITT_CONFIG_FILE}"

# Validate action
[[ "${MODE}" =~ ^post-hp$|^pre-is$|^post-is$ ]] || usage

# MODE is required
if [[ -z ${MODE} ]]; then
  logError "Mode must be specified with -m <post-hp|pre-is|post-is>" 1
fi

if [ "${MODE}" == "post-hp" ]; then
  SKIP_JENKINS=1
else
  if [ -n "${JENKINS_USERNAME}" ]; then
    JENKINS_CREDENTIALS="${JENKINS_USERNAME}:${JENKINS_PASSWORD}@"
  fi
fi

# Check required variables are settings
checkVars
echo "${BOLD}Starting HITT in ${MODE} mode...${NORMAL}"

# Check command line tools present
logStatus "Checking for required tools in path..."
checkRequiredTools
# Remove
cleanUp
logStatus "Checking namespaces..."
if [ "${HP_NAMESPACE}" == "${IS_NAMESPACE}" ]; then
  logError "Helix Platform and Helix IS must be installled in seperate namespaces." 1
fi
checkHPNamespace "${HP_NAMESPACE}"
if [ "${MODE}" != "post-hp" ]; then
  checkISNamespace "${IS_NAMESPACE}"
fi
logStatus "Getting versions..."
getVersions
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
checkTenantRealms
logStatus "Validating realm..."
validateRealm

if [ "${MODE}" != "post-hp" ]; then
  logStatus "Getting IS details..."
  getISDetailsFromK8s
  getISDetailsFromJenkins
  logStatus "Validating IS details..."
  validateISDetails
  logStatus "Checking IS registry details..."
  checkISDockerLogin
  logStatus "Validating IS cacerts..."
  validateCacerts
fi

if [ "${SKIP_JENKINS}" == "0" ]; then
  logStatus "Checking IS FTS Elastic settings..."
  checkFTSElasticSettings
  logStatus "Checking IS DB settings..."
  checkISDBSettings
fi

if [ "${MODE}" == "post-is" ]; then
  logStatus "Checking IS license status..."
  checkISLicenseStatus
  logStatus "Checking Support Assistant Tool..."
  checkAssistTool
fi

cleanUp
reportResults
# DEBUG only
dumpVARs
