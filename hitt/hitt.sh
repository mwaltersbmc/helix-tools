#!/usr/bin/env bash

# Helix IS Triage Tool (HITT) shell script to validate settings for Helix onprem - pre and post deployment
# Mark Walters SEAL Team May '24

# FUNCTIONS Start

# Populate HP_NS_CANDIDATES / IS_NS_CANDIDATES from cluster (rsso / midtier-user deployments).
# Uses NS_ARRAY; skips the PENDING sentinel (not a real namespace name).
discoverHelixNamespaceCandidates() {
  logMessage "Scanning namespaces..."
  HP_NS_CANDIDATES=()
  IS_NS_CANDIDATES=()
  CDE_NS_CANDIDATES=()
  HL_NS_CANDIDATES=()
  local ns
  for ns in "${NS_ARRAY[@]}"; do
    [[ "${ns}" == "PENDING" ]] && continue
    if ${KUBECTL_BIN} -n "${ns}" get deployment rsso >/dev/null 2>&1; then
      HP_NS_CANDIDATES+=("${ns}")
    fi
    if ${KUBECTL_BIN} -n "${ns}" get deployment midtier-user >/dev/null 2>&1; then
      IS_NS_CANDIDATES+=("${ns}")
    fi
    if ${KUBECTL_BIN} -n "${ns}" get deployment jenkins-master >/dev/null 2>&1; then
      CDE_NS_CANDIDATES+=("${ns}")
    fi
    if ${KUBECTL_BIN} -n "${ns}" get sts efk-elasticsearch-data >/dev/null 2>&1; then
      HL_NS_CANDIDATES+=("${ns}")
    fi
  done
}

# $1 = candidates array name; prints chosen namespace on stdout
selectFromCandidatesOrOther() {
  local candidates_name="${1}"
  local candidates_ref="${candidates_name}[@]"
  local candidates=("${!candidates_ref}")
  local menu_options=("${candidates[@]}" "${NAMESPACE_OTHER_OPTION}")
  local choice

  choice=$(selectFromArray menu_options)
  if [[ "${choice}" == "${NAMESPACE_OTHER_OPTION}" ]]; then
    selectFromArray NS_ARRAY
  else
    echo "${choice}"
  fi
}

# $1 = variable name to assign (e.g. HP_NAMESPACE)
# $2 = candidates array name (e.g. HP_NS_CANDIDATES)
# $3 = label for prompts (e.g. "Helix Platform")
# $4 = optional: when the sole candidate equals this value, skip y/n and show candidate menu with Other
confirmOrSelectNamespace() {
  local result_var="${1}"
  local candidates_name="${2}"
  local label="${3}"
  local skip_if_equals="${4:-}"
  local candidates_ref="${candidates_name}[@]"
  local candidates=("${!candidates_ref}")
  local selected=""

  if [ ${#candidates[@]} -eq 1 ]; then
    if [[ -n "${skip_if_equals}" && "${candidates[0]}" == "${skip_if_equals}" ]]; then
      :
    else
      logStatus "Found one ${label} namespace candidate: ${candidates[0]}" 1
      if askYesNo "Use namespace '${candidates[0]}'?"; then
        printf -v "${result_var}" '%s' "${candidates[0]}"
        logStatus "Selected ${label} namespace: ${!result_var}" 1
        return
      fi
    fi
  fi

  if [ ${#candidates[@]} -ge 1 ]; then
    logStatus "Please select your ${label} namespace..." 1
    selected=$(selectFromCandidatesOrOther "${candidates_name}")
    printf -v "${result_var}" '%s' "${selected}"
    return
  fi

  logStatus "Please select your ${label} namespace..." 1
  selected=$(selectFromArray NS_ARRAY)
  printf -v "${result_var}" '%s' "${selected}"
}

getEPjson() {
  # getxxx svc/ing namespace
  if ${KUBECTL_BIN} auth can-i get nodes --quiet &>/dev/null; then
    NODE_IP=$(${KUBECTL_BIN} get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
  else
    NODE_IP="Node IP not found - set manually in hitt config file."
  fi

  ${KUBECTL_BIN} get svc,ing -n "${2}" -o json | ${JQ_BIN} --arg name "${1}" --arg nip "${NODE_IP}" '[
    # Process Ingresses
    (.items[] | select(.kind == "Ingress" and .metadata.name == $name and (.status.loadBalancer.ingress | length > 0)) | {
      type: "ingress",
      name: .metadata.name,
      version: .metadata.labels["helix-de/version"],
      host: (.spec.rules[0].host),
      protocol: "https",
      port: 443
    }),
    # Exposed Services
    (.items[] | select(.kind == "Service" and .metadata.name == $name and (.spec.externalIPs | length > 0)) | {
      type: "exposed IP",
      name: .metadata.name,
      version: .metadata.labels["helix-de/version"],
      host: .spec.externalIPs[0],
      # Find port for the port named "http"
      protocol: "http",
      port: (.spec.ports[] | select(.name == "http") | .port)
    }),
    # NodePorts
    (.items[] | select(.kind == "Service" and .metadata.name == $name and (.spec.type == "NodePort")) | {
      type: "nodeport",
      name: .metadata.name,
      version: .metadata.labels["helix-de/version"],
      host: $nip,
      # Find the nodePort for the port named "http"
      protocol: "http",
      port: (.spec.ports[] | select(.name == "http" ) | .nodePort)
    })
  ]'
}

getConfValues() {
  JENKINS_PROTOCOL_ARRAY=(http https)
  if [ "${MODE}" == "pre-hp" ] || [ "${MODE}" == "info" ]; then
    NS_ARRAY=("PENDING" "${NS_ARRAY[@]}")
  fi
  discoverHelixNamespaceCandidates

  confirmOrSelectNamespace HP_NAMESPACE HP_NS_CANDIDATES "Helix Platform"
  confirmOrSelectNamespace IS_NAMESPACE IS_NS_CANDIDATES "Helix IS" "${HP_NAMESPACE}"

  logStatus "Please enter your HELIX_ONPREM_DEPLOYMENT pipeline CUSTOMER_SERVICE and ENVIRONMENT values:" 1
  #read -p "CUSTOMER_SERVICE : " IS_CUSTOMER_SERVICE
  while [[ -z "${IS_CUSTOMER_SERVICE}" ]]; do read -p "CUSTOMER_SERVICE : " IS_CUSTOMER_SERVICE; done
  #read -p "ENVIRONMENT : " IS_ENVIRONMENT
  while [[ -z "${IS_ENVIRONMENT}" ]]; do read -p "ENVIRONMENT : " IS_ENVIRONMENT; done

  JENKINS_LOCATION_ARRAY=("Locally on this Deployment Engine system." "Remotely as a Containerized Deployment Engine pod in the Kubernetes cluster.")
  logStatus "Where is Jenkins running?"
  selectFromArray JENKINS_LOCATION_ARRAY
  if [ "${REPLY}" != "1" ]; then

    confirmOrSelectNamespace CDE_NAMESPACE CDE_NS_CANDIDATES "Jenkins"
    # CDE - check for end points
    JENKINS_EP_JSON=$(getEPjson jenkins-master "${CDE_NAMESPACE}")
    JENKINS_CDE_VERSION=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r '.[0].version')
    echo
    logStatus "Jenkins CDE version: ${JENKINS_CDE_VERSION}"
    K8S_JENKINS=1
    mapfile -t JENKINS_EP_ARRAY < <(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r '.[] | "\(.host) on port \(.port) (via \(.type))"')
    if [ ${#JENKINS_EP_ARRAY[@]} -eq 1 ]; then
      JENKINS_HOSTNAME=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r '.[0].host')
      JENKINS_PROTOCOL=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r '.[0].protocol')
      JENKINS_PORT=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r '.[0].port')
    else
      logStatus "Please select your preferred Jenkins connection..." 1
      selectFromArray JENKINS_EP_ARRAY
      JENKINS_HOSTNAME=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r --argjson element "${REPLY}" '.[$element-1].host')
      JENKINS_PROTOCOL=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r --argjson element "${REPLY}" '.[$element-1].protocol')
      JENKINS_PORT=$(echo "${JENKINS_EP_JSON}" | ${JQ_BIN} -r --argjson element "${REPLY}" '.[$element-1].port')
    fi
#  logStatus "Please enter your Jenkins details:"
#  while [[ -z "${JENKINS_HOSTNAME}" ]]; do read -p "Jenkins hostname or IP address : " JENKINS_HOSTNAME; done
#    echo "Jenkins protocol :"
#    JENKINS_PROTOCOL=$(selectFromArray JENKINS_PROTOCOL_ARRAY)
#    [[ "${JENKINS_PROTOCOL}" == "https" ]] && JENKINS_PORT_NUM=443 || JENKINS_PORT_NUM=8080
#    read -p "Jenkins port number [${JENKINS_PORT_NUM}]: " JENKINS_PORTX
#    JENKINS_PORT=${JENKINS_PORTX:-$JENKINS_PORT_NUM}
  else
    JENKINS_HOSTNAME=localhost
    JENKINS_PROTOCOL=http
    JENKINS_PORT=8080
  fi
  logMessage "Jenkins server - ${JENKINS_PROTOCOL}://${JENKINS_HOSTNAME}:${JENKINS_PORT}"

  if isJenkinsInCluster ; then
    JENKINS_CREDS_JSON=$(${KUBECTL_BIN} -n "${CDE_NAMESPACE}" get secret jenkins-master-admin -o jsonpath='{.data}')
    JENKINS_USERNAME=$(echo "${JENKINS_CREDS_JSON}" | ${JQ_BIN} -r '.username | @base64d')
    JENKINS_PASSWORD=$(echo "${JENKINS_CREDS_JSON}" | ${JQ_BIN} -r '.password | @base64d')
    logMessage "Auto configured Jenkins credentials."
  else
    logStatus "Please enter your Jenkins GUI username and password if required, otherwise just press return:" 1
    read -p "Username : " JENKINS_USERNAME
    read -r -s -p "Password : " JENKINS_PASSWORD
  fi
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
CDE_NAMESPACE=${CDE_NAMESPACE}

# OPTIONAL SETTINGS
# Set JENKINS credentials and hostname/port if required
# Enclose username/password in single quotes to avoid issues with special characters
JENKINS_USERNAME='${JENKINS_USERNAME}'
JENKINS_PASSWORD='${JENKINS_PASSWORD}'
JENKINS_HOSTNAME=${JENKINS_HOSTNAME}
JENKINS_PROTOCOL=${JENKINS_PROTOCOL}
JENKINS_PORT=${JENKINS_PORT}

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
HOST_BIN=host
ZIP_BIN=zip
UNZIP_BIN=unzip
EOF

if [ ! -f "${1}" ]; then
  logError "227" "Failed to create '${1}' file - please check you have permissions to create files in the current directory." 1
fi
}

logError() {
  # Print error message MSG_ID MSG / exit if value of 1 passed as third parameter
  stopOnError "${1}"
  MSG="${BOLD}${RED}ERROR${NORMAL} (${1}) - ${2}"
  [[ "${QUIET}" == "0" ]] && echo -e "${MSG}" >&2
  ((FAIL++))
  ERROR_ARRAY+=("(${1}) - ${2}")
  logMessageDetails "${1}" "${MSG}"
  if [ -z "${IGNORE_ERRORS}" ] && [ "${3}" == "1" ] ; then exit 1; fi
}

logWarning() {
  # Print warning message MSG_ID MSG
  stopOnError "${1}"
  MSG="${BOLD}${YELLOW}WARNING${NORMAL} (${1}) - ${2}"
  [[ "${QUIET}" == "0" ]] && echo -e "${MSG}" >&2
  ((WARN++))
  WARN_ARRAY+=("(${1}) - ${2}")
  logMessageDetails "${1}" "${MSG}"
}

logMessage() {
  # Print message
  if [ -z "${2}" ]; then
    MSG_LEVEL=0
  else
    MSG_LEVEL=${2}
  fi
  [[ ${MSG_LEVEL} -le ${VERBOSITY} ]] && [[ "${QUIET}" == "0" ]] && echo -e "\t${1}"
}

# Second arg optional: pass 1 to print even when QUIET=1 (otherwise only prints when QUIET=0).
logStatus() {
  if [[ "${QUIET}" == "0" ]] || [[ "${2}" == "1" ]]; then
    echo -e "\n${BOLD}${1}${NORMAL}"
  fi
}

hittTerminalLink() {
  # OSC 8 hyperlink for supported terminals (Windows Terminal, iTerm2, etc.); $1 = URL, $2 = label.
  printf '\033]8;;%s\033\\%s\033]8;;\033\\' "${1}" "${2}"
}

stopOnError() {
  if [ "${STOP_ON_ERROR}" == "${1}" ] || [ "${STOP_ON_ERROR}" == "0" ]; then
    exit
  fi
}

usage() {
    echo ""
    echo -e "${BOLD}Helix IS Triage Tool (HITT)${NORMAL}"
    echo -e "${BOLD}Usage: bash $0 -m <post-hp|pre-is|post-is|jenkins>${NORMAL}"
    echo ""
    echo "Examples:"
    echo "bash $0 -m post-hp  - run post HP installation only checks"
    echo "OR"
    echo "bash $0 -m pre-is   - run pre-installation checks"
    echo "OR"
    echo "bash $0 -m post-is  - run post-installation checks"
    echo "OR"
    echo "bash $0 -m jenkins  - run Jenkins configuration checks"
    echo ""
    echo -e "Use ${BOLD}post-hp${NORMAL} after successfully installing the Helix Platform but before using Jenkins."
    echo -e "Use ${BOLD}pre-is${NORMAL} after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS."
    echo -e "Use ${BOLD}post-is${NORMAL} for troubleshooting after IS deployment."
    echo -e "Use ${BOLD}jenkins${NORMAL} to validate Jenkins config - nodes, credentials, libraries etc."
    echo
    echo -e "${BOLD}Interactive help page with HITT use-cases available at https://bit.ly/hitthelp${NORMAL}"
    echo
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
  if [ -n "${MISSING}" ] ; then
    logError "999" "One or more required tools not found - cannot continue." 1
  fi
}

checkCLITools() {
  local MISSING_CLI M1 M2
  MISSING_CLI=()
  CLI_BINS=("awk" "sed" "grep" "cut" "tr" "head" "tail" "wc" "column" "find" "file" "getent" "date" "hostname" "timeout" "mktemp" "md5sum" "chmod" "mkdir" "cp" "touch" "stat" "rm" "dirname" "basename" "xargs" "whoami" "ssh")
  for i in "${CLI_BINS[@]}"; do
    if ! which "${i}" >/dev/null 2>&1; then
      MISSING_CLI+=("${i}")
    fi
  done
  if [[ "${#MISSING_CLI[@]}" -gt 0 ]]; then
    M1="tools"
    M2="they are"
    [[ "${#MISSING_CLI[@]}" -eq 1 ]] && M1="tool" && M2="this is"
    logError "999" "Missing command line ${M1} '${MISSING_CLI[*]}' - HITT commands and results are likely to be unreliable unless ${M2} installed."
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
        MISSING=1
      fi
      ;;
    java)
      REQUIRED_VERSION=11
      INSTALLED_VERSION=$(${JAVA_BIN} -version 2>&1 | grep -oP 'version "?(1\.)?\K\d+')
      JAVA_VERSION="${INSTALLED_VERSION}"
      if compare "${INSTALLED_VERSION} < ${REQUIRED_VERSION}"; then
        logError "101" "java version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed."
        MISSING=1
      fi
      ;;
    kubectl)
      REQUIRED_VERSION=1.20
      KUBECTL_JSON=$(${KUBECTL_BIN} version -o json 2>>${HITT_ERR_FILE})
      INSTALLED_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.clientVersion.major + "." + .clientVersion.minor')
      KUBECTL_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.clientVersion.gitVersion')
      K8S_VERSION=$(echo "${KUBECTL_JSON}" | ${JQ_BIN} -r '.serverVersion.gitVersion')
      if compare "${INSTALLED_VERSION} < ${REQUIRED_VERSION}"; then
        logError "101" "kubectl version ${REQUIRED_VERSION} or later required - version ${INSTALLED_VERSION} installed."
        MISSING=1
      fi
      ;;
    *)
      ;;
  esac
}

checkBinary() {
  if ! which "${1}" > /dev/null 2>&1 ; then
    logError "105" "${1} command not found in path. Please set ${1^^}_BIN variable with the full path to the file."
  else
    logMessage "${1} command found ($(which ${1}))." 1
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
    rm -f "./${i}"
  done
  for i in "${CLEANUP_DIRS[@]}"; do
    rm -rf "./${i}"
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
      logError "106" "${NS_TYPE} namespace '${1}' not found." 1
    else
      logMessage "${NS_TYPE} namespace '${1}' found." 1
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
    logError "107" "Deployment ${DEPLOYMENT} not found in '${1}' - please check the ${NS_TYPE} namespace name." 1
  else
    logMessage "${NS_TYPE} namespace is '${1}'."
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
      logError "108" "Registry secret not found in ${1} namespace - HELIX_GENERATE_CONFIG pipeline must be run to enable all ${MODE} checks."
    fi
  fi
  if [ "${MODE}" == "post-is" ]; then
    if ! ${KUBECTL_BIN} -n "${1}" get secret cacerts > /dev/null 2>&1 ; then
      logError "107" "cacerts secret not found in '${1}' namespace - please check the ${NS_TYPE} namespace name." 1
    fi
  fi
  logMessage "${NS_TYPE} namespace is '${1}'."
  checkPodStatus "${1}"
}

checkPodStatus() {
  BAD_PODS=($(${KUBECTL_BIN} -n "${1}" get pod --field-selector=status.phase!=Succeeded -o json | ${JQ_BIN} -r '.items[] | select(.status.containerStatuses[]?.ready == false) | .metadata.name' 2>>${HITT_ERR_FILE}))
  #if [ $(${KUBECTL_BIN} -n "${1}"  get pods -o custom-columns=":metadata.name,:status.containerStatuses[*].state.waiting.reason" | grep -v "<none>" | wc -l) != "1" ]; then
  if [ "${#BAD_PODS[@]}" != "0" ]; then
     logError "102" "One or more pods in the '${1}' namespace found in a non-ready state."
     [[ "${QUIET}" -ne 1 ]] && ${KUBECTL_BIN} -n "${1}" get pods "${BAD_PODS[@]}"
     for i in "${BAD_PODS[@]}"; do
       logDescribePod "${1}" "${i}"
     done
  else
    logMessage "No unhealthy pods found in the '${1}' namespace." 1
  fi
}

logDescribePod() {
  # ns / pod name
  ${KUBECTL_BIN} -n "${1}" describe pod "${2}" > "k8s-desc-pod-${1}-${2}.log" 2>>${HITT_ERR_FILE}
}

getVersions() {
  isOpenShift
  logMessage "Kubernetes version '${K8S_VERSION}'."
  logMessage "kubectl version '${KUBECTL_VERSION}'."
  if [ "${OPENSHIFT_VERSION}" != "" ]; then
    logMessage "OpenShift version '${OPENSHIFT_VERSION}'."
  fi
  HELM_VERSION=$(helm version --short 2>/dev/null)
  logMessage "Helm version '${HELM_VERSION}'."
  if [ -f /etc/os-release ]; then
    OS_NAME=$(grep "^NAME=" /etc/os-release | cut -d '=' -f2)
    OS_VERSION=$(grep "^VERSION=" /etc/os-release | cut -d '=' -f2)
    logMessage "Running on ${OS_NAME} version ${OS_VERSION}."
  fi
  HP_CONFIG_MAP_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm helix-on-prem-config -o json 2>>${HITT_ERR_FILE})
  if [ "${HP_CONFIG_MAP_JSON}" == "" ]; then
    logError "999" "Unable to read the 'helix-on-prem-config' configMap from the Helix Platform namespace - cannot continue until the Platform is installed." 1
  fi
  HP_VERSION=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.version' | head -1)
  HP_INGRESS_CLASS=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.infra_config' | grep ^INGRESS_CLASS | cut -d '=' -f2)
  HP_CUSTOM_CERT=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.infra_config' | grep ^CUSTOM_CA_SIGNED_CERT_IN_USE | cut -d '=' -f2)
  HP_DEPLOYMENT_SIZE=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.deployment_config' | grep ^DEPLOYMENT_SIZE | cut -d '=' -f2)
  HP_REGISTRY_PROJECT=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.deployment_config' | grep ^IMAGE_REGISTRY_PROJECT | cut -d '=' -f2)
  logMessage "Helix Platform version '${HP_VERSION}' with DEPLOYMENT_SIZE '${HP_DEPLOYMENT_SIZE}'."
  if [[ ! "${HP_DEPLOYMENT_SIZE}" =~ ^itsm.* ]]; then
    logWarning "002" "Helix Platform DEPLOYMENT_SIZE is '${HP_DEPLOYMENT_SIZE}' - expected to be itsmcompact/itsmsmall/itsmxlarge unless additional ITOM products are/will be installed."
  fi
  HP_SM_PLATFORM_CORE=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.deployment_config' | grep ^SM_PLATFORM_CORE | cut -d '=' -f2)
  NUM_TMS_PODS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pod -l app=tms 2>/dev/null | wc -l)
  if [ "${HP_SM_PLATFORM_CORE}"  == "yes" ] || [ "${NUM_TMS_PODS}"  == "0" ] ; then
    logMessage "Helix Platform CORE deployment for ITSM only." 1
    HP_SM_PLATFORM_CORE=yes
  else
    HP_SM_PLATFORM_CORE=no
  fi

  if [ "${MODE}" == "post-is" ]; then
    IS_VERSION=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.metadata.labels.chart}' | cut -f2 -d '-')
    logMessage "Helix IS version '${IS_VERSION}'."
    setISDBVersion "${IS_VERSION}"
  fi
}

setISDBVersion() {
  # Set expected currDbVersion
  case "${1%%.*}" in
    21)
      IS_DB_VERSION=199
      ;;
    22)
      IS_DB_VERSION=200
      ;;
    23)
      IS_DB_VERSION=201
      [[ "${1}" == "23.3.04" ]] && IS_DB_VERSION=203
      ;;
    25)
      [[ "${1}" == "25.1.01" ]] && IS_DB_VERSION=203
      [[ "${1}" == "25.2.01" ]] && IS_DB_VERSION=215
      [[ "${1}" == "25.3.01" ]] && IS_DB_VERSION=215
      [[ "${1}" == "25.4.01" ]] && IS_DB_VERSION=216
      ;;
    26)
      [[ "${1}" == "26.1.01" ]] && IS_DB_VERSION=236
      [[ "${1}" == "26.2.01" ]] && IS_DB_VERSION=237
      ;;
    *)
      logError "109" "Unknown Helix IS version '${IS_VERSION}' - please check https://bit.ly/gethitt for HITT updates." 1
  esac
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
  TMS_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress helix-tms-ingress-master -o jsonpath='{.spec.rules[0].host}')
  MINIO_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress minio -o jsonpath='{.spec.rules[0].host}')
  MINIO_API_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress minio-api -o jsonpath='{.spec.rules[0].host}')
  KIBANA_LB_HOST=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress efk-elasticsearch-kibana -o jsonpath='{.spec.rules[0].host}' 2>/dev/null)
  LOG_ELASTICSEARCH_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret logelasticsearchsecret -o jsonpath='{.data}')
  FTS_ELASTIC_SERVICENAME=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_CLUSTER | @base64d' | cut -d ':' -f 1)
  LOG_ELASTICSEARCH_PASSWORD=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_PASSWORD | @base64d')
  LOG_ELASTICSEARCH_USERNAME=$(echo ${LOG_ELASTICSEARCH_JSON} | ${JQ_BIN} -r '.LOG_ELASTICSEARCH_USERNAME | @base64d')
  #FTS_ELASTIC_POD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get endpoints "${FTS_ELASTIC_SERVICENAME}" -o=jsonpath='{.subsets[*].addresses[0].ip}' | xargs -I % ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pods --field-selector=status.podIP=% -o jsonpath='{.items[0].metadata.name}')
  FTS_ELASTIC_POD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pods -l "$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get svc "${FTS_ELASTIC_SERVICENAME}" -o jsonpath='{.spec.selector}' | ${JQ_BIN} -r 'to_entries | map("\(.key)=\(.value)") | join(",")')" --no-headers -o custom-columns=NAME:.metadata.name 2>/dev/null | head -n 1)
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
      TCTL_REST_VER=110
      ADE_INFRA_CLIENT_IMAGE_TAG=22201-1-v4-ade-infra-clients-1
      ;;
    22.4)
      TCTL_REST_VER=230
      ADE_INFRA_CLIENT_IMAGE_TAG=22400-v9-ade-infra-clients-1
      ;;
    23.1.02)
      TCTL_REST_VER=255
      ADE_INFRA_CLIENT_IMAGE_TAG=23102-v3-ade-infra-clients-1
      ;;
    23.2.02)
      TCTL_REST_VER=310
      ADE_INFRA_CLIENT_IMAGE_TAG=23202-v1-ade-infra-clients-1
      ;;
    23.4.00)
      TCTL_REST_VER=370
      ADE_INFRA_CLIENT_IMAGE_TAG=23400-v2-ade-infra-clients-1
      ;;
    24.1.00)
      TCTL_REST_VER=420
      ADE_INFRA_CLIENT_IMAGE_TAG=24100-v5-ade-infra-clients-1
      ;;
    24.2.00)
      TCTL_REST_VER=472
      ADE_INFRA_CLIENT_IMAGE_TAG=24200-v6-ade-infra-clients-alpine
      ;;
    24.3.00)
      TCTL_REST_VER=529
      ADE_INFRA_CLIENT_IMAGE_TAG=24300-v46-ade-infra-clients-alpine
      ;;
    24.4.00)
      TCTL_REST_VER=574
      ADE_INFRA_CLIENT_IMAGE_TAG=24400-v71-ade-infra-clients-alpine
      ;;
    25.1.00)
      TCTL_REST_VER=614
      ADE_INFRA_CLIENT_IMAGE_TAG=25100-v151-ade-infra-clients-alpine
      ;;
    25.2.00)
      TCTL_REST_VER=654
      ADE_INFRA_CLIENT_IMAGE_TAG=25200-v97-ade-infra-clients-alpine
      ;;
    25.3.00)
      TCTL_REST_VER=685
      ADE_INFRA_CLIENT_IMAGE_TAG=25300-v232-ade-infra-clients-alpine
      ;;
    25.4.00)
      TCTL_REST_VER=724
      ADE_INFRA_CLIENT_IMAGE_TAG=25400-v335-ade-infra-clients-alpine
      ;;
    26.1.00)
      TCTL_REST_VER=737
      ADE_INFRA_CLIENT_IMAGE_TAG=26100-v1-ade-infra-clients-alpine
      ;;
    26.2.01)
      TCTL_REST_VER=1695
      ADE_INFRA_CLIENT_IMAGE_TAG=26201-v692-ade-infra-clients-alpine
      ;;
    *)
      ;;
  esac
  # TCTL_REST_VER in compact.config ADE_INFRA_CLIENT_IMAGE_TAG in infra/infra-images-tag.config

  HP_COMPANY_NAME_LABEL="COMPANY_NAME"
  if compare "${HP_VERSION%.*} >= 24.2" ; then
    HP_COMPANY_NAME_LABEL="TENANT_NAME"
  fi
  HP_COMPANY_NAME=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.infra_config' | grep "^${HP_COMPANY_NAME_LABEL}" | cut -d '=' -f2)

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

  if compare "${HP_VERSION%.*} == 24.4" ; then
    ZOOKEEPER_IMG=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get sts kafka-zookeeper -o jsonpath='{.spec.template.spec.containers[?(@.name=="zookeeper")].image}')
    if [ "${ZOOKEEPER_IMG#*:}" == "24400-v71-bitnami-zookeeper-3.9.1-alpine-jdk11" ]; then
      logError "223" "Helix Platform 24.4 is installed but the 24.4.00.001 hotfix has not been applied - please download this update from the BMC EPD and install it."
    fi
  fi

  if compare "${HP_VERSION%.*} >= 25.4" ; then
    HP_TENANT_ACTIVATED_STATUS="REG_AUTOCOMPLETED"
  else
    HP_TENANT_ACTIVATED_STATUS="REG_COMPLETED"
  fi

  if compare "${HP_VERSION%.*} >= 26.1" ; then
    ARSERVICES_MSG="SM_PLATFORM_CORE"
  else
    ARSERVICES_MSG="ARSERVICES"
  fi
}

getRSSODetails() {
  RSSO_ADMIN_TAS_CM=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm rsso-admin-tas -o json)
  RSSO_URL=$(echo "$RSSO_ADMIN_TAS_CM" | ${JQ_BIN} -r '.data.rssourl + "/rsso"')
  logMessage "RSSO URL is '${RSSO_URL}'."
  RSSO_USERNAME=$(echo "$RSSO_ADMIN_TAS_CM" | ${JQ_BIN} -r '.data.username')
  logMessage "RSSO username is '${RSSO_USERNAME}'." 1
  RSSO_PASSWORD=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret rsso-admin-tas -o jsonpath='{.data.password}' | ${BASE64_BIN} -d)
  RSSO_TOKEN_JSON=$(${JQ_BIN} -n --arg u "${RSSO_USERNAME}" --arg p "${RSSO_PASSWORD}" '{username: $u, password: $p}' | \
    ${CURL_BIN} -sk -X POST "${RSSO_URL}/api/v1.1/admin/login" \
      -H 'Content-Type: application/json' \
      --data-binary @-)
  if [[ "${RSSO_TOKEN_JSON}" =~ "admin_token" ]]; then
    RSSO_TOKEN=$(echo "${RSSO_TOKEN_JSON}" | ${JQ_BIN} -r .admin_token)
    logMessage "RSSO login OK - got admin token." 1
  else
    logError "112" "Unable to get the RSSO admin token. RSSO response: ${RSSO_TOKEN_JSON}" 1
  fi
}

getDomain() {
  # CLUSTER_DOMAIN=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment tms -o jsonpath='{.spec.template.spec.containers[?(@.name=="tms")].env[?(@.name=="DOMAIN_NAME")].value}')
  CLUSTER_DOMAIN=$(echo "${HP_CONFIG_MAP_JSON}" | ${JQ_BIN} -r '.data.infra_config' | grep ^DOMAIN | cut -d '=' -f2)
  [[ "${MODE}" =~ ^p ]] && logMessage "Helix domain is '${CLUSTER_DOMAIN}'."
}

checkHelixLoggingDeployed() {
  HELIX_LOGGING_DEPLOYED=0
  HELIX_LOGGING_NAMESPACES=($(${KUBECTL_BIN} get deployment -A | grep efk-elasticsearch-kibana | awk '{print $1}' 2>/dev/null))
  if [ "${#HELIX_LOGGING_NAMESPACES[@]}" -gt 1 ]; then
    echo "Multiple Helix Logging instances found - please select the namespace you wish to use:"
    HELIX_LOGGING_NAMESPACE=$(selectFromArray HELIX_LOGGING_NAMESPACES)
  else
    HELIX_LOGGING_NAMESPACE="${HELIX_LOGGING_NAMESPACES[0]}"
  fi
  if [ -n "${HELIX_LOGGING_NAMESPACE}" ]; then
    HELIX_LOGGING_DEPLOYED=1
    HELIX_LOGGING_PASSWORD=$(${KUBECTL_BIN} -n "${HELIX_LOGGING_NAMESPACE}" get secret efk-elasticsearch-kibana -o json  | ${JQ_BIN} -r '.data["kibana-password"] | @base64d')
    HELIX_LOGGING_PASSWORD_URI=$(printf %s "${HELIX_LOGGING_PASSWORD}" | ${JQ_BIN} -sRr @uri)
    HELIX_LOGGING_VERSION=$(${KUBECTL_BIN} -n "${HELIX_LOGGING_NAMESPACE}" get ds efk-fluent-bit -o json | ${JQ_BIN} -r '.spec.template.spec.containers[0].image | split(":")[1] | split("-")[0]') || HELIX_LOGGING_VERSION="unknown"
    logMessage "Helix Logging version '${HELIX_LOGGING_VERSION}' found in the '${HELIX_LOGGING_NAMESPACE}' namespace."
    checkEFKClusterHealth
  else
    HELIX_LOGGING_NAMESPACE=""
    logMessage "Helix Logging not found."
    if ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm helix-on-prem-config -o jsonpath='{.data.bmc_helix_logging_config}' | grep -q 'ENABLE_LOG_SHIPPER_IN_PODS=true'; then
      logWarning "003" "ENABLE_LOG_SHIPPER_IN_PODS=true - consider installing Helix Logging to reduce error messages in Helix Platform pod logs."
    fi
  fi
}

checkEFKClusterHealth() {
  EFK_ELASTIC_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" ${FTS_ELASTIC_POD_CONTAINER} -- sh -c "curl -sk -X GET https://elastic:${HELIX_LOGGING_PASSWORD_URI}@${EFK_ELASTIC_SERVICENAME}.${HELIX_LOGGING_NAMESPACE}:9200/_cluster/health")
  EFK_ELASTIC_STATUS=$(echo "${EFK_ELASTIC_JSON}" | ${JQ_BIN} -r '.status')
  if ! echo "${EFK_ELASTIC_STATUS}" | grep -q green ; then
    logError "113" "Helix Logging Elasticsearch problem. Check the '${EFK_ELASTIC_SERVICENAME}' pods in the '${HELIX_LOGGING_NAMESPACE}' namespace."
  else
    logMessage "Helix Logging Elasticsearch '${EFK_ELASTIC_SERVICENAME}.${HELIX_LOGGING_NAMESPACE}' appears healthy." 1
  fi
}

getTenantDetails() {
  if [ "${HP_SM_PLATFORM_CORE}"  == "yes" ]; then
    logMessage "Helix Platform CORE deployment for ITSM - skipping tenant checks..."
    HP_TENANT="core"
    return
  fi
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
  logMessage "Helix Platform tenant is '${HP_TENANT}'."
  PORTAL_HOSTNAME=$(echo "${TENANT_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${HP_TENANT}'").host')
  if isTenantActivated ; then
    logMessage "Tenant has been activated."
  else
    logWarning "041" "Tenant has not been activated."
  fi
  logMessage "Helix Portal hostname is '${PORTAL_HOSTNAME}'."
  HP_COMPANY_NAME=$(echo "${HP_TENANT%%.*}")
  logMessage "Helix Platform ${HP_COMPANY_NAME_LABEL} is '${HP_COMPANY_NAME}'."
}

isTenantActivated() {
  # HP_TENANT
  PG_POD=$(getPodNameByLabel "${HP_NAMESPACE}" "application=patroni,data=pool")
  TENANT_STATUS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PG_POD}" -- psql -d ade_rsso -U postgres -tc "select status from localuser where realm='${HP_TENANT}'" 2>/dev/null)
  echo "${TENANT_STATUS}" | grep -q "REG_.*COMPLETED"
}

checkPlatformSSL() {
  TAS_POD=$(getPodNameByLabel "${HP_NAMESPACE}" "app=tas")
  if ! ${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${TAS_POD}" -- sh -c "curl --cacert /apps/data/cacerts https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}" &>/dev/null; then
    logError "257" "Helix Platform custom_cacert.pem file does not appear to be valid for the Service Management aliases."
  else
    logMessage "Helix Platform custom_cacert.pem appears valid for Service Management aliases." 1
  fi
}

selectFromArray() {
  local ARRAY_REF="${1}[@]"
  local options=("${!ARRAY_REF}")

  # PS3 is the prompt displayed by the select command
  local OLD_PS3="${PS3}"
  PS3="Select a valid option (1-${#options[@]}): "

  select i in "${options[@]}"; do
    if [[ -n "${i}" ]]; then
      echo "${i}"
      PS3="${OLD_PS3}" # Restore original prompt
      break
    else
      echo "Error: '${REPLY}' is not a valid choice." >&2
    fi
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
    TCTL_IMAGE="${HP_REGISTRY_SERVER}/bmc/tctlrest-${TCTL_REST_VER}"
    return 1
  else
    TCTL_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get job "${TCTL_JOB_NAME}" -o json)
    #  TCTL_IMAGE=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get job "${TCTL_JOB_NAME}" -o jsonpath='{.spec.template.spec.containers[0].image}')
    TCTL_IMAGE=$(echo ${TCTL_JSON} | ${JQ_BIN} -r '.spec.template.spec.containers[0].image')
  #  TCTL_RUNASUSER=$(echo ${TCTL_JSON} | ${JQ_BIN} -r '.spec.template.spec.containers[0].securityContext.runAsUser')
  #  TCTL_RUNASGROUP=$(echo ${TCTL_JSON} | ${JQ_BIN} -r '.spec.template.spec.containers[0].securityContext.runAsGroup')
    if [ -z "${TCTL_IMAGE}" ]; then
      logError "203" "Unable to get TCTL image name from job ${TCTL_JOB_NAME}."
      return 1
    fi
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
#          runAsUser: ${TCTL_RUNASUSER}
#          runAsGroup: ${TCTL_RUNASGROUP}
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
    debugTCTLJob
    logError "204" "Timed out waiting for job ${SEALTCTL} to complete."
    return 1
  else
    return 0
  fi
}

# Extract JSON body from sealtctl job pod logs (tctl prints a "Response: {...}" block for -o json).
extractTctlJsonFromLogText() {
  awk '
      /Response: *\{/ {
        json_started=1
        depth=1
        line = substr($0, index($0, "{"))
        print line
        next
      }
      json_started {
        print
        depth += gsub(/{/, "{")
        depth -= gsub(/}/, "}")
        if (depth == 0) exit
      }
    ' 2>/dev/null
}

debugTCTLJob() {
  echo -e "\nJob description:" >sealtctl.log
  ${KUBECTL_BIN} -n "${HP_NAMESPACE}" describe job/"${SEALTCTL}" 2>/dev/null >>sealtctl.log
  echo -e "\nGet pods:" >>sealtctl.log
  ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get pods --selector=job-name="${SEALTCTL}" 2>/dev/null >>sealtctl.log
  echo -e "\nDescribe pods:" >>sealtctl.log
  ${KUBECTL_BIN} -n "${HP_NAMESPACE}" describe pods --selector=job-name="${SEALTCTL}" 2>/dev/null >>sealtctl.log
  echo -e "\nJob logs:" >>sealtctl.log
  ${KUBECTL_BIN} -n "${HP_NAMESPACE}" logs job/${SEALTCTL} 2>/dev/null >>sealtctl.log
}

getRealmDetails() {
  REALM_NAME="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
  RSSO_REALM=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}")
  if echo "${RSSO_REALM}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    logError "116" "SSO realm '${REALM_NAME}' not found for SAAS_TENANT in RSSO.  Check realm names and the IS_CUSTOMER_SERVICE/IS_ENVIRONMENT values in hitt.conf."
    echo "Realms found in RSSO are:"
    ${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms -H "Authorization: RSSO ${RSSO_TOKEN}" | ${JQ_BIN} -r '" - " + .realms[].id'
    exit 1
  else
    logMessage "SSO realm '${REALM_NAME}' found for the SAAS_TENANT." 1
  fi
}

checkTenantRealms() {
  if [ "${HP_SM_PLATFORM_CORE}"  == "yes" ]; then
    return
  fi
  TENANT_REALM=$(${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}" -H "X-RSSO-TENANT-IMP: ${PORTAL_HOSTNAME}")
  if ! echo "${TENANT_REALM}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    logError "117" "Helix IS realm '${REALM_NAME}' exists for tenant '${HP_TENANT}' when it should be configured for the SAAS_TENANT."
#  else
#    logMessage "Verified Helix IS realm '${REALM_NAME}' is not configured for tenant ${HP_TENANT}."
  fi
}

validateRealm() {
  logMessage "Using realm '${REALM_NAME}'"
  # Parse realm data
  REALM_ARHOST=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arHost)
  if [ "${REALM_ARHOST}" != "platform-user-ext.${IS_NAMESPACE}" ]; then
    logError "118" "Invalid arHost value in realm - expected 'platform-user-ext.${IS_NAMESPACE}' but found '${REALM_ARHOST}'."
  else
    logMessage "AR host '${REALM_ARHOST}' is the expected value." 1
  fi
  REALM_ARPORT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .authChain.idpAr[0].arPort)
  if [ "${REALM_ARPORT}" != "46262" ]; then
    logError "119" "Invalid arPort in realm - expected 46262 but found ${REALM_ARPORT}."
  else
    logMessage "AR port '${REALM_ARPORT}' is the expected value." 1
  fi
  REALM_TENANT=$(echo "${RSSO_REALM}" | ${JQ_BIN} -r .tenantDomain)
  if [ "${REALM_TENANT}" == "" ]; then
    logError "232" "RSSO realm Tenant is blank - recommended value is '${HP_TENANT}'."
  else
    if [ "${REALM_TENANT}" != "${HP_TENANT}" ] && [ "${HP_SM_PLATFORM_CORE}"  == "no" ]; then
      logWarning "004" "Unexpected TENANT value in realm - recommended value is '${HP_TENANT}' but found '${REALM_TENANT}'."
    else
      logMessage "TENANT is '${REALM_TENANT}'." 1
    fi
  fi
  REALM_DOMAINS=($(echo "${RSSO_REALM}" | ${JQ_BIN} -r '.domainMapping.domain[]' | tr "\n" " "))
  BAD_DOMAINS=0
  validateRealmDomains
  if [ "${BAD_DOMAINS}" == "1" ] && [ "${VERBOSITY}" == "1" ]; then
    logMessage "Application Domains found in SSO Realm '${REALM_NAME}' are:"
    printf '  %s\n' "${REALM_DOMAINS[@]}"
  fi
}

buildISAliasesArray() {
  if [ "${IS_ENVIRONMENT}" == "prod" ]; then
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}"
    logMessage "ENVIRONMENT value is 'prod' - IS hostnames prefix is '${IS_ALIAS_PREFIX}-.'" 1
  else
    IS_ALIAS_PREFIX="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
    logMessage "IS hostnames prefix is '${IS_ALIAS_PREFIX}'." 1
  fi
  # Midtier alias
  IS_ALIAS_ARRAY+=("${IS_ALIAS_PREFIX}.${CLUSTER_DOMAIN}")
  # Add other IS aliases
  for i in "${IS_ALIAS_SUFFIXES[@]}"; do
    IS_ALIAS_ARRAY+=("${IS_ALIAS_PREFIX}-${i}.${CLUSTER_DOMAIN}")
  done
}

validateRealmDomains() {
  logMessage "Checking for expected hostname aliases in realm Application Domains, DNS & Helix certificate..." 1
  # Check for wildcard certain
  if ${OPENSSL_BIN} s_client -connect "${LB_HOST}:443" ${OPENSSL_PROXY_STRING} </dev/null 2>/dev/null | ${OPENSSL_BIN} x509 -noout -text | grep "DNS:" | grep -Fq "*.${CLUSTER_DOMAIN}" ; then
    logMessage "Helix certificate is a wildcard for '*.${CLUSTER_DOMAIN}'." 1
    WILDCARD_CERT=1
  else
    WILDCARD_CERT=0
  fi

  ADE_ALIAS_ARRAY=("${LB_HOST}" "${TMS_LB_HOST}" "${MINIO_LB_HOST}" "${MINIO_API_LB_HOST}")
  [[ -n "${PORTAL_HOSTNAME}" ]] && ADE_ALIAS_ARRAY+=("${PORTAL_HOSTNAME}")
  [[ -n "${KIBANA_LB_HOST}" ]] && ADE_ALIAS_ARRAY+=("${KIBANA_LB_HOST}")
  for i in "${ADE_ALIAS_ARRAY[@]}"; do
    validateAliasInDNS "${i}"
    validateAliasInLBCert "${i}"
    if [ "${i}" != "${PORTAL_HOSTNAME}" ]; then
      if echo "${REALM_DOMAINS[@]}" | grep -q "${i}"; then
        logError "229" "The Helix Platform alias '${i}' should not be included in the SSO realm Application Domains list."
      fi
    fi
  done

  buildISAliasesArray
  # Check for midtier alias
  for TARGET in "${IS_ALIAS_ARRAY[@]}"; do
    if ! echo "${REALM_DOMAINS[@]}" | grep -q "${TARGET}" ; then
      if echo "${TARGET}" | grep -q reporting ; then
        MSG_SUFFIX="Note: only required for ITSM 25.3.01 and later."
      fi
      logError "120" "Alias '${TARGET}' not found in Application Domains list. ${MSG_SUFFIX}"
      MSG_SUFFIX=""
      BAD_DOMAINS=1
    else
      logMessage "  - alias '${TARGET}' found in realm Application Domains list." 1
    fi
    validateAliasInDNS "${TARGET}"
    validateAliasInLBCert "${TARGET}"
    validateAliasAccessibleFromDE "${TARGET}"
  done

  # Check for portal alias - will not be present if INTEROPS pipeline has not been run
  if ! echo "${REALM_DOMAINS[@]}" | grep -q "${PORTAL_HOSTNAME}" ; then
    logWarning "005" "Alias '${PORTAL_HOSTNAME}' not found in the realm Application Domains list. This is expected until the HELIX_ITSM_INTEROPS pipeline has completed."
  fi
  # Should not be present in pre-is unless INTEROPS run
  if [ "${SM_PLATFORM_CORE}" == "no" ] && [ "${MODE}" == "pre-is" ] && echo "${REALM_DOMAINS[@]}" | grep -q "${PORTAL_HOSTNAME}"; then
    logWarning "037" "Alias '${PORTAL_HOSTNAME}' found in the realm Application Domains list. This is expected after the HELIX_ITSM_INTEROPS pipeline has completed."
  fi
}

validateAliasAccessibleFromDE(){
  HTTP_CODE=$(${CURL_BIN} -ks -o /dev/null -w "%{http_code}" --max-time 3 "https://${1}")
  case "${HTTP_CODE}" in
    200|201|202|204|404|409|302)
      logMessage "  - url 'https://${1}' is accessible from the this system." 1
      ;;
    *)
      if echo "${1}" | grep -q reporting ; then
        MSG_SUFFIX="Note: alias only applies to ITSM 25.3.01 and later."
      fi
      logWarning "043" "URL 'https://${1}' did not return an expected response code - '${HTTP_CODE}'. ${MSG_SUFFIX}"
      MSG_SUFFIX=""
      ;;
  esac
}

validateAliasInDNS() {
  # hostname to check
  if ! ${HOST_BIN} ${1} > /dev/null 2>>${HITT_ERR_FILE}; then
    if echo "${1}" | grep -q reporting ; then
      MSG_SUFFIX="Note: only required for ITSM 25.3.01 and later."
    fi
    logError "122" "Entry for '${1}' not found in DNS. ${MSG_SUFFIX}"
    MSG_SUFFIX=""
  else
    logMessage "  - alias '${1}' found in DNS." 1
  fi
}

validateAliasInLBCert() {
  # Check that alias is valid for the cert used in LB/NGINX
  # 1/alias
  [[ "${WILDCARD_CERT}" == "1" ]] && return
  if ! ${OPENSSL_BIN} s_client -connect "${1}:443" ${OPENSSL_PROXY_STRING} </dev/null 2>/dev/null | ${OPENSSL_BIN} x509 -noout -text | grep "DNS:" | grep -q "${1}" ; then
    if echo "${1}" | grep -q reporting ; then
      MSG_SUFFIX="Note: only required for ITSM 25.3.01 and later."
    fi
    logError "218" "Alias '${1}' is not present as a SAN in the Helix certificate. ${MSG_SUFFIX}"
    MSG_SUFFIX=""
  else
    logMessage "  - alias '${1}' found in the Helix certificate." 1
  fi
}

logLBCertDetails() {
  ${OPENSSL_BIN} s_client -connect  "${LB_HOST}:443" ${OPENSSL_PROXY_STRING} </dev/null 2>/dev/null > cert-lb-host.log
  ${OPENSSL_BIN} s_client -connect  "${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}:443" ${OPENSSL_PROXY_STRING} </dev/null 2>/dev/null > cert-restapi.log
}

checkServiceDetails() {
  if [ "${HP_SM_PLATFORM_CORE}" == "yes" ]; then
    logMessage "Helix Platform CORE deployment for ITSM - skipping ARSERVICES checks..."
    return
  fi
  deleteTCTLJob
  if ! deployTCTL "get service"; then
    logError "123" "Failed to get Helix Platform ARSERVICES status."
    return
  fi
  getTCTLOutput
  if ! echo "${TCTL_OUTPUT}" | grep -q "^ITSM "  ; then
    logError "124" "ITSM services not found in Helix Platform - please check that ${ARSERVICES_MSG}=yes was set in your deployment.config file."
  else
    logMessage "ITSM services found in Helix Platform." 1
  fi
  if ! echo "${TCTL_OUTPUT}" | grep -q "^ITSMInsight"  ; then
    logMessage "ITSM Insights services are not installed." 1
    ITSM_INSIGHTS=1
  else
    logMessage "ITSM Insights services found in Helix Platform." 1
    ITSM_INSIGHTS=0
  fi
  deleteTCTLJob
}

checkFTSElasticStatus() {
  FTS_ELASTIC_STATUS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${FTS_ELASTIC_POD}" ${FTS_ELASTIC_POD_CONTAINER} -- sh -c "curl -sk -u \"${LOG_ELASTICSEARCH_USERNAME}:${LOG_ELASTICSEARCH_PASSWORD}\" -X GET https://localhost:9200/_cluster/health?pretty | grep status")
  if ! echo "${FTS_ELASTIC_STATUS}" | grep -q green ; then
    logError "125" "FTS Elasticsearch problem. Check the ${FTS_ELASTIC_SERVICENAME} pods in Helix Platform namespace."
  else
    logMessage "FTS Elasticsearch '${FTS_ELASTIC_SERVICENAME}' appears healthy." 1
  fi
}

getISDetailsFromK8s() {
  [[ "${MODE}" != "post-is" && "${MODE}" != "info" ]] && return
  logMessage "Getting data from IS namespace..."
  IS_PLATFORM_STS=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.containers[?(@.name=="platform")]}')
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret ar-global-secret > /dev/null 2>&1; then
    IS_PLATFORM_SECRET=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret ar-global-secret -o jsonpath='{.data}')
    IS_AR_DB_USER=$(getValueFromPlatformSecret "AR_DB_USERNAME")
    IS_AR_DB_PASSWORD=$(getValueFromPlatformSecret "AR_DB_PASSWORD")
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_PLATFORM_SECRET}" | ${JQ_BIN} -r '.CACERTS_PASSWORD')
  else
    IS_PLATFORM_SECRET=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret platform-fts -o jsonpath='{.data}')
    IS_AR_DB_USER=$(getValueFromPlatformSecret "AR_SERVER_DB_USERNAME")
    IS_AR_DB_PASSWORD=$(getValueFromPlatformSecret "AR_SERVER_DB_USER_PASSWORD")
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=$(echo "${IS_PLATFORM_SECRET}" | ${JQ_BIN} -r '.CACERTS_SSL_TRUSTSTORE_PASSWORD')
  fi
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
  JENKINS_RESCODE=$(${CURL_BIN} -k -s -o /dev/null -w "%{http_code}" "${JENKINS_URL}")
  case "${JENKINS_RESCODE}" in
    200)
      JENKINS_RESPONSE=$(${CURL_BIN} -skI "${JENKINS_URL}")
      JENKINS_VERSION=$(echo "${JENKINS_RESPONSE}" | grep -i 'X-Jenkins:' | awk '{print $2}' | tr -d '\r')
      logMessage "Jenkins version ${JENKINS_VERSION} found on ${JENKINS_LOG_URL:-$JENKINS_URL}"
      getJenkinsCrumb
      ;;
    401|403)
      logError "127" "Jenkins authentication is enabled but the credentials in hitt.conf are blank or wrong.  Please set correct credentials in the HITT config file '${HITT_CONFIG_FILE}'." 1
      SKIP_JENKINS=1
      ;;
    *)
      logError "126" "Jenkins not found on ${JENKINS_LOG_URL} - skipping Jenkins tests."
      if ! isJenkinsInCluster; then
        systemctl status jenkins > jenkins-status.log 2>&1
      fi
      SKIP_JENKINS=1
      ;;
  esac
  if [ "$1" == "1" ] && [ "${SKIP_JENKINS}" == "1" ]; then
    logStatus "Can't continue without access to Jenkins."
    exit 1
  fi
}

getLastBuildFromJenkins() {
  # PIPELINE_NAME
  BUILD_NUMBER=$(${CURL_BIN} -sk "${JENKINS_URL}/job/${1}/lastBuild/buildNumber")
  echo "${BUILD_NUMBER}"
}

savePipelineConsoleOutput() {
  # PIPELINE_NAME / BUILD_NUMBER
  ${CURL_BIN} -skf "${JENKINS_URL}/job/${1}/${2}/consoleText" > "${1}.log"
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
  JENKINS_JSON=$(${CURL_BIN} -sk "${JENKINS_URL}/job/HELIX_ONPREM_DEPLOYMENT/lastBuild/api/json")
  checkJenkinsJobResult
  JENKINS_ONPREM_DEPLOYMENT_LASTBUILD=$(getLastBuildFromJenkins HELIX_ONPREM_DEPLOYMENT)
  JENKINS_GENERATE_CONFIG_LASTBUILD=$(getLastBuildFromJenkins HELIX_GENERATE_CONFIG)
  logMessage "Last pipeline build numbers are - HELIX_ONPREM_DEPLOYMENT/${JENKINS_ONPREM_DEPLOYMENT_LASTBUILD} and HELIX_GENERATE_CONFIG/${JENKINS_GENERATE_CONFIG_LASTBUILD}." 1
  JENKINS_PARAMS=$(getPipelineValuesJSON getLastBuild)
  #JENKINS_PARAMS=$(echo "${JENKINS_JSON}" | ${JQ_BIN} -r '.actions[] | select(._class=="hudson.model.ParametersAction") .parameters[]')
  getPipelineValues
}

checkJenkinsJobResult() {
  if ! echo "${JENKINS_JSON}" | ${JQ_BIN} -r .result | grep -q "SUCCESS"; then
    logWarning "006" "Last build of the HELIX_ONPREM_DEPLOYMENT pipeline was not successful. Please review the console output for this and the HELIX_GENERATE_CONFIG pipelines - saved in the HITT directory."
  fi
}

parseJenkinsParam() {
  echo "${JENKINS_PARAMS}" | ${JQ_BIN} -r ".${1}"
  #echo "${JENKINS_PARAMS}" | ${JQ_BIN} -r ' . | select(.name=="'"$1"'") .value'
}

createPipelineVarsArray() {
  PIPELINE_VARS=(
    CHECKOUT_USING_USER
    CUSTOM_BINARY_PATH
    GIT_USER_HOME_DIR
    CONTAINERIZED_DE
    GIT_REPO_DIR
    HELM_NODE
    IS_CLOUD
    ROUTE_ENABLED
    ROUTE_TLS_ENABLED
    CLUSTER
    CLUSTER_CONTEXT
    IS_NAMESPACE
#    CUSTOMER_NAME - removed as may have spaces
    INGRESS_CLASS
    CLUSTER_DOMAIN
    APPLICATION_PARENT_DOMAIN
    INPUT_CONFIG_METHOD
    DEPLOYMENT_MODE
    DEPLOYMENT_TYPE
    CUSTOMER_SIZE
    ENVIRONMENT_SIZE
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
    DB_JDBC_URL
    DATABASE_RESTORE
    DATABASE_HOST_NAME
    DATABASE_ADMIN_USER
    ORACLE_SERVICE_NAME
    DATABASE_RESTORE
    IS_DATABASE_ALWAYS_ON
    LOGS_ELASTICSEARCH_HOSTNAME
    LOGS_ELASTICSEARCH_TLS
    OS_RESTRICTED_SCC
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
    CACERTS_SSL_TRUSTSTORE_PASSWORD
    LOGS_ELASTICSEARCH_PASSWORD
    IMAGE_REGISTRY_PASSWORD
    DATABASE_ADMIN_PASSWORD
    AR_DB_PASSWORD
    PLATFORM_SR_DB_PASSWORD
    FTS_ELASTICSEARCH_USER_PASSWORD
    BAKEDUSER_HANNAH_ADMIN_PASSWORD
    AR_SERVER_APP_SERVICE_PASSWORD
    AR_SERVER_DSO_USER_PASSWORD
    AR_SERVER_MIDTIER_SERVICE_PASSWORD
    VC_RKM_PASSWORD
    VC_PROXY_USER_PASSWORD
    RSSO_ADMIN_PASSWORD
    AR_SERVER_ALIAS
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
  ${CURL_BIN} -sk "${JENKINS_URL}/jnlpJars/jenkins-cli.jar" -o jenkins-cli.jar
  if [ ! -f jenkins-cli.jar ]; then
    logError "999" "Failed to download jenkins-cli.jar file from Jenkins." 1
  fi
}

getPipelinePasswords() {
  SCRIPT='import jenkins.model.*
    import hudson.model.*
    def jobName = "HELIX_ONPREM_DEPLOYMENT"
    def jenkins = Jenkins.instance
    def job = jenkins.getItemByFullName(jobName)
    def lastBuild = job.getLastBuild()
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
  runJenkinsScript "${SCRIPT}"
}

checkSSHSetup() {
  validateSSHPermissions
  checkSSHknown_hosts
  checkJenkinsSSH
}

checkJenkinsSSH() {
  RESULT=$(runJenkinsSSH)
  if [ "${RESULT}" != "${USER}" ]; then
    logError "236" "Passwordless SSH test from Jenkins pipeline as the git user failed - please check that the jenkins user can run 'ssh ${USER}@${LONG_HOSTNAME}' without any input."
  fi
}

runJenkinsSSH() {
  SCRIPT="def output=['bash', '-c', 'ssh -o StrictHostKeyChecking=accept-new ${USER}@${LONG_HOSTNAME} whoami'].execute().text.trim()
    println output"
  runJenkinsScript "${SCRIPT}"
}

setVarsFromPipelineJSON() {
  # Parse and export variables
for key in $(echo "$json" | ${JQ_BIN} -r 'keys[]'); do
    value=$(echo "$json" | ${JQ_BIN} -r --arg key "$key" '.[$key]')
    varname="IS_$key"
    printf -v "${varname}" '%s' "${value}"
    export "${varname}"
    echo "${varname}=${value}"
done
}

getPipelineValues() {
  createPipelineVarsArray
  for i in "${PIPELINE_VARS[@]}"; do
    printf -v "IS_${i}" '%s' "$(parseJenkinsParam "${i}")"
  done
  IS_PIPELINE_VERSION="${IS_PLATFORM_HELM_VERSION:2:2}.${IS_PLATFORM_HELM_VERSION:4:1}.${IS_PLATFORM_HELM_VERSION:5:2}"
  IS_VERSION="${IS_PLATFORM_HELM_VERSION:0:7}"
  # 25.3.01 renamed parameters
  if [ "${IS_VERSION}" -ge 2025301 ]; then
    IS_CLUSTER="${IS_CLUSTER_CONTEXT}"
    IS_CLUSTER_LABEL="CLUSTER_CONTEXT"
    IS_CLUSTER_DOMAIN="${IS_APPLICATION_PARENT_DOMAIN}"
    IS_CLUSTER_DOMAIN_LABEL="APPLICATION_PARENT_DOMAIN"
    IS_CUSTOMER_SIZE="${IS_ENVIRONMENT_SIZE}"
    IS_CUSTOMER_SIZE_LABEL="ENVIRONMENT_SIZE"
    IS_PIPELINE_MODE="${IS_DEPLOYMENT_TYPE}"
    IS_PIPELINE_MODE_LABEL="DEPLOYMENT_TYPE"
  else
    IS_CLUSTER_LABEL="CLUSTER"
    IS_CLUSTER_DOMAIN_LABEL="CLUSTER_DOMAIN"
    IS_CUSTOMER_SIZE_LABEL="CUSTOMER_SIZE"
    IS_PIPELINE_MODE="${IS_DEPLOYMENT_MODE}"
    IS_PIPELINE_MODE_LABEL="DEPLOYMENT_MODE"
  fi
  if [ "${IS_VERSION}" -ge 2026201 ]; then
    IS_CONTAINERIZED_DE="true"
    IS_CUSTOM_BINARY_PATH="false"
    #IS_AGENT="jenkins-agent"
    IS_CHECKOUT_USING_USER="github"
    #IS_KUBECONFIG_CREDENTIAL="kubeconfig"
    IS_GIT_USER_HOME_DIR="/home/jenkins"
    #IS_GIT_REPO_DIR="http://gitea:3000/ciadmin"
    IS_HELM_NODE="jenkins-agent"
    IS_REGISTRY_TYPE="DTR"
  fi

  ISP_CUSTOMER_SERVICE=$(parseJenkinsParam CUSTOMER_SERVICE)
  ISP_ENVIRONMENT=$(parseJenkinsParam ENVIRONMENT)
  if isBlank "${ISP_CUSTOMER_SERVICE}" || isBlank "${ISP_ENVIRONMENT}" ; then
    logError "128" "CUSTOMER_SERVICE and/or ENVIRONMENT are blank - please enter all required values in the HELIX_ONPREM_DEPLOYMENT pipeline." 1
  fi
  if ! isRFC1123 "${ISP_CUSTOMER_SERVICE}" ; then
    logError "258" "The CUSTOMER_SERVICE value '${ISP_CUSTOMER_SERVICE}' is not valid - it should consist of lower case alphanumeric, '-' or '.' characters."
  fi
  if ! isRFC1123 "${ISP_ENVIRONMENT}" ; then
    logError "258" "The ENVIRONMENT value '${ISP_ENVIRONMENT}' is not valid - it should consist of lower case alphanumeric, '-' or '.' characters."
  fi

  if [[ "${IS_CUSTOMER_SIZE}" =~ M ]] || [[ "${IS_CUSTOMER_SIZE}" =~ L ]]; then
    IS_PLATFORM_INT=1
  fi
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi
  #IS_IMAGE_REGISTRY_PASSWORD=$(getPipelinePasswords | ${JQ_BIN} -r '.IMAGE_REGISTRY_PASSWORD.plainText')
  setISDBVersion "${IS_PIPELINE_VERSION}"
  #cloneCustomerConfigsRepo
  cloneGitRepos
}

checkPipelinePwds() {
  [[ "${SKIP_JENKINS}" == "1" ]] && return
  if [ "${MODE}" != "pre-is" ]; then return; fi
  PASSWDS_JSON=$(getPipelinePasswords | ${JQ_BIN} 'to_entries')
  return # next bit no longer valid?
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
    printf -v "IS_${i}" '%s' "$(grepInputFile "${i}")"
  done
  IS_DATABASE_ADMIN_PASSWORD="${IS_DB_ADMIN_PASSWORD}"
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

getGITEACredentials() {
  SCRIPT='import groovy.json.JsonBuilder
    def env = System.getenv()
    def result = [
        GITEA_ADMIN_USER: env.get("GITEA_ADMIN_USER") ?: "Not Found",
        GITEA_ADMIN_PASS: env.get("GITEA_ADMIN_PASS") ?: "Not Found"
    ]
    def json = new JsonBuilder(result)
    println json.toPrettyString()'
    runJenkinsScript "${SCRIPT}"
}

cloneGitRepos() {
  SKIP_REPO=0
  export GIT_SSH_COMMAND="ssh -oBatchMode=yes"
  GIT_REPO_DIR=$(parseJenkinsParam GIT_REPO_DIR)
  INPUT_CONFIG_FILE="configsrepo/customer/${IS_CUSTOMER_SERVICE}/${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}.sh"

  if isJenkinsInCluster ; then
    GITEA_CREDS_JSON=$(getGITEACredentials)
    GITEA_ADMIN_USER=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_USER')
    GITEA_ADMIN_PASS=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_PASS')
    GITEA_EP_JSON=$(getEPjson gitea "${CDE_NAMESPACE}")
    GITEA_HOST=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].host')
    GITEA_PROTOCOL=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].protocol')
    GITEA_PORT=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].port')
    GITEA_URL="${GITEA_PROTOCOL}://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}:${GITEA_PORT}"
#    #Check for GITEA ingress
#    GITEA_HOST=$(${KUBECTL_BIN} get ingress -A -o custom-columns=":metadata.name,:.spec.rules[*].host" --no-headers | grep ^gitea | awk '{print $2}')
#    if [ -n "${GITEA_HOST}" ] ; then
#      GITEA_URL="https://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}"
#    fi
#    # If ingress not found check for exposed svc
#    if [ -z "${GITEA_HOST}" ] ; then
#      GITEA_HOST=$(${KUBECTL_BIN} get svc -A -o custom-columns=":metadata.name,:.spec.externalIPs[0]" --no-headers| grep ^gitea | awk '{print $2}')
#      if [ -n "${GITEA_HOST}" ] && [ "${GITEA_HOST}" != "<none>" ]; then
#        GITEA_URL="http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}:3000"
#      else
#        GITEA_HOST=""
#      fi
#    fi
    if [ -z "${GITEA_HOST}" ] ; then
      logMessage "Unable to find GITEA host connection details - skipping checks."
      SKIP_REPO=1
      return
    fi
    if ! ${GIT_BIN} -c http.sslVerify=false clone "${GITEA_URL}/${GITEA_ADMIN_USER}/onprem-remedyserver-config" configsrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone CUSTOMER_CONFIGS from GITEA."
      SKIP_REPO=1
      return
    else
      logMessage "Cloned CUSTOMER_CONFIGS to configsrepo directory." 1
    fi
    if ! ${GIT_BIN} -c http.sslVerify=false clone "${GITEA_URL}/${GITEA_ADMIN_USER}/itsm-on-premise-installer" itsmrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone ITSM_REPO from GITEA."
      SKIP_REPO=1
      return
    else
      logMessage "Cloned ITSM_REPO to itsmrepo directory." 1
    fi
  else
    if ! ${GIT_BIN} clone "${GIT_REPO_DIR}"/CUSTOMER_CONFIGS/onprem-remedyserver-config.git configsrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone ${GIT_REPO_DIR}/CUSTOMER_CONFIGS/onprem-remedyserver-config.git"
      SKIP_REPO=1
      return
    else
      logMessage "Cloned CUSTOMER_CONFIGS repo to configsrepo directory." 1
    fi
    if ! ${GIT_BIN} clone "${GIT_REPO_DIR}/ITSM_REPO/itsm-on-premise-installer.git" itsmrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone ${GIT_REPO_DIR}/ITSM_REPO/itsm-on-premise-installer.git"
      SKIP_REPO=1
      return
    else
      logMessage "Cloned ITSM_REPO to itsmrepo directory." 1
    fi
  fi
  if [ ! -f "${INPUT_CONFIG_FILE}" ]; then
    logError "130" "Input configuration file '${INPUT_CONFIG_FILE}' not found. Has the HELIX_GENERATE_CONFIG pipeline been run successfully?"
    SKIP_REPO=1
    return
  else
    logMessage "Input config file found '${INPUT_CONFIG_FILE}'." 1
    #getInputFileValues
  fi
}

cloneCustomerConfigsRepo() {
  SKIP_REPO=0
  export GIT_SSH_COMMAND="ssh -oBatchMode=yes"
  GIT_REPO_DIR=$(parseJenkinsParam GIT_REPO_DIR)
  INPUT_CONFIG_FILE="configsrepo/customer/${IS_CUSTOMER_SERVICE}/${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}.sh"
  if isJenkinsInCluster ; then
    GITEA_CREDS_JSON=$(getGITEACredentials)
    GITEA_ADMIN_USER=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_USER')
    GITEA_ADMIN_PASS=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_PASS')
    #Check for GITEA ingress
    GITEA_HOST=$(${KUBECTL_BIN} get ingress -A -o custom-columns=":metadata.name,:.spec.rules[*].host" --no-headers | grep ^gitea | awk '{print $2}')
    if [ -n "${GITEA_HOST}" ] ; then
      GITEA_URL="https://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}"
    fi
    # If ingress not found check for exposed svc
    if [ -z "${GITEA_HOST}" ] ; then
      GITEA_HOST=$(${KUBECTL_BIN} get svc -A -o custom-columns=":metadata.name,:.spec.externalIPs[0]" --no-headers| grep ^gitea | awk '{print $2}')
      if [ -n "${GITEA_HOST}" ] && [ "${GITEA_HOST}" != "<none>" ]; then
        GITEA_URL="http://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}:3000"
      else
        GITEA_HOST=""
      fi
    fi
    if [ -z "${GITEA_HOST}" ] ; then
      logMessage "Unable to find GITEA host connection details - skipping checks."
      SKIP_REPO=1
      return
    fi
    if ! ${GIT_BIN} -c http.sslVerify=false clone "${GITEA_URL}/${GITEA_ADMIN_USER}/onprem-remedyserver-config" configsrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone CUSTOMER_CONFIGS from GITEA."
      SKIP_REPO=1
      return
    else
      logMessage "Cloned CUSTOMER_CONFIGS repo to configsrepo directory." 1
    fi
  else
    if ! ${GIT_BIN} clone "${GIT_REPO_DIR}"/CUSTOMER_CONFIGS/onprem-remedyserver-config.git configsrepo > /dev/null 2>&1 ; then
      logError "129" "Failed to clone ${GIT_REPO_DIR}/CUSTOMER_CONFIGS/onprem-remedyserver-config.git"
      SKIP_REPO=1
      return
    else
      logMessage "Cloned CUSTOMER_CONFIGS repo to configsrepo directory." 1
    fi
  fi
  if [ ! -f "${INPUT_CONFIG_FILE}" ]; then
    logError "130" "Input configuration file '${INPUT_CONFIG_FILE}' not found. Has the HELIX_GENERATE_CONFIG pipeline been run successfully?"
    SKIP_REPO=1
    return
  else
    logMessage "Input config file found '${INPUT_CONFIG_FILE}'." 1
    #getInputFileValues
  fi
}

isBlank() {
  [[ -z "${1}" ]] && return 0 || return 1
}

checkBlank() {
  if isBlank "${!1}"; then
    logError "131" "Value for '${1:3}' is not expected to be blank."
  else
    logMessage "Value set for '${1:3}'." 1
  fi
}

validateISDetails() {
  [[ "${SKIP_JENKINS}" == "1" ]] && return
  # Common to pre and post
  if [ "${IS_TENANT_DOMAIN}" != "${REALM_TENANT}" ] && [ "${REALM_TENANT}" != "" ] ; then
    logError "132" "TENANT_DOMAIN '${IS_TENANT_DOMAIN}' does not match the Helix Platform realm Tenant '${REALM_TENANT}'."
  else
    logMessage "TENANT_DOMAIN matches the realm Tenant '${REALM_TENANT}'." 1
  fi

  if [[ "${IS_RSSO_URL}" != https* ]]; then
    logError "264" "The RSSO_URL value in the HELIX_ONPREM_DEPLOYMENT pipeline '${IS_RSSO_URL}' does not start with the required 'https://'."
  fi
  if [ "${IS_RSSO_URL}" != "${RSSO_URL}" ]; then
    logError "133" "The RSSO_URL value in the HELIX_ONPREM_DEPLOYMENT pipeline '${IS_RSSO_URL}' does not match the Helix Platform RSSO_URL '${RSSO_URL}'."
  else
    logMessage "IS RSSO_URL is the expected value of '${RSSO_URL}'." 1
  fi

  if [ "${#IS_AR_SERVER_APP_SERVICE_PASSWORD}" -gt 19 ]; then
    logError "134" "AR_SERVER_APP_SERVICE_PASSWORD is too long - maximum of 19 characters."
  else
    logMessage "AR_SERVER_APP_SERVICE_PASSWORD length is 19 characters or less." 1
  fi

  if [ "${#IS_AR_SERVER_DSO_USER_PASSWORD}" -gt 20 ]; then
    logError "135" "AR_SERVER_DSO_USER_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_DSO_USER_PASSWORD length is 20 characters or less." 1
  fi

  if [ "${#IS_AR_SERVER_MIDTIER_SERVICE_PASSWORD}" -gt 20 ]; then
    logError "135" "AR_SERVER_MIDTIER_SERVICE_PASSWORD is too long - maximum of 20 characters."
  else
    logMessage "AR_SERVER_MIDTIER_SERVICE_PASSWORD length is 20 characters or less." 1
  fi

  # PRE mode only
  if [ "${MODE}" == "pre-is" ]; then
    logMessage "HELIX_ONPREM_DEPLOYMENT pipeline version is '${IS_PLATFORM_HELM_VERSION}'."
    logMessage "${IS_CUSTOMER_SIZE_LABEL} is '${IS_CUSTOMER_SIZE}'."
    logMessage "${IS_PIPELINE_MODE_LABEL} is '${IS_PIPELINE_MODE}'."
    if [ "${IS_VERSION}" -ge 2025301 ]; then
      logMessage "DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}'."
    fi
    if [ "${IS_CHECKOUT_USING_USER}" != "github" ]; then
      logError "220" "CHECKOUT_USING_USER is not set to the expected value of the Jenkins credentials ID used to access the git repository files - usually 'github'."
    fi

    if [ "${OPENSHIFT}" == "1" ]; then
      if [ "${IS_OS_RESTRICTED_SCC}" != "true" ]; then
        logWarning "042" "OS_RESTRICTED_SCC is not selected - this is usually required for OpenShift clusters."
      fi
    fi

    if isJenkinsInCluster && [ "${IS_CONTAINERIZED_DE}" != "true" ]; then
      logError "253" "CONTAINERIZED_DE must be selected when Jenkins/GITEA are containerized."
    fi

    if ! isJenkinsInCluster && [ "${IS_CONTAINERIZED_DE}" = "true" ]; then
        logError "254" "CONTAINERIZED_DE is only valid when Jenkins/GITEA are containerized."
    fi

    if [[ ! "${IS_GIT_USER_HOME_DIR}" =~ ^/.* ]]; then
      logError "244" "GIT_USER_HOME_DIR value '${IS_GIT_USER_HOME_DIR}' is not valid - it must be an absolute path beginning with '/' - eg: '/home/git'."
    fi

    if [ "${IS_GIT_USER_HOME_DIR}" == "" ]; then
      logError "131" "GIT_USER_HOME_DIR value cannot be blank."
    else
      if isJenkinsInCluster ; then
        if [ "${IS_GIT_USER_HOME_DIR}" != "/home/jenkins" ]; then
          logError "255" "GIT_USER_HOME_DIR value '${IS_GIT_USER_HOME_DIR}' is not valid for containerized Jenkins - must be '/home/jenkins'."
        fi
      else
        if [ ! -d "${IS_GIT_USER_HOME_DIR}" ]; then
          logError "222" "GIT_USER_HOME_DIR value '${IS_GIT_USER_HOME_DIR}' is not a valid directory."
        fi
      fi
    fi

    if isJenkinsInCluster ; then
      if [ "${IS_GIT_REPO_DIR}" != "http://gitea:3000/${GITEA_ADMIN_USER}" ]; then
        logError "256" "GIT_REPO_DIR value must be 'http://gitea:3000/${GITEA_ADMIN_USER}' for containerized Jenkins."
      fi
    else
      if [[ ! "${IS_GIT_REPO_DIR}" =~ ^ssh://.* ]]; then
        logError "221" "GIT_REPO_DIR value is blank or not in the expected format of 'ssh://<Jenkins server host name>/home/git/git_repo'."
      else
        REPO_PATH=$(echo ${IS_GIT_REPO_DIR} | sed -e 's#ssh://[^/]*##')
        if [ ! -d "${REPO_PATH}" ]; then
          logError "224" "The directory used in the GIT_REPO_DIR value '${IS_GIT_REPO_DIR}' is not valid."
        fi
      fi
    fi

    if [ "${IS_GIT_REPO_DIR: -1}" == "/" ]; then
      logError "226" "GIT_REPO_DIR value ends with a '/' character which will cause an error - please remove it."
    fi

    if [ "${IS_PIPELINE_MODE}" == "UPGRADE" ] || [ "${IS_PIPELINE_MODE}" == "UPDATE" ]; then
      CURRENT_VER=$(echo "${IS_SOURCE_VERSION}" | tr -d .)
      TARGET_VER=$(echo "${IS_PLATFORM_HELM_VERSION}" | tr -d .)
      if [ "${CURRENT_VER}" -ge "${TARGET_VER}" ]; then
        logError "213" "SOURCE_VERSION is greater than or equal to the PLATFORM_HELM_VERSION but ${IS_PIPELINE_MODE_LABEL} is '${IS_PIPELINE_MODE}'."
      fi

      # UPDATE is always valid for applying a HF
      # eg 202330410000 / 202330410400 / 202330410400
      if [ "${CURRENT_VER:0:9}" -eq "${TARGET_VER:0:9}" ] && [ "${IS_PIPELINE_MODE}" != "UPDATE" ]; then
        logError "213" "${IS_PIPELINE_MODE_LABEL} should be 'UPDATE' when applying a hotfix but is set to '${IS_PIPELINE_MODE}'."
      fi

      # UPDATE should be used for any 2330x updates with same major release
      # eg 20233 0410000 / 20233 0410400 / 20233 0410400
      if [ "${CURRENT_VER:0:5}" -eq "${TARGET_VER:0:5}" ] && [ "${IS_PIPELINE_MODE}" != "UPDATE" ]; then
        logError "213" "${IS_PIPELINE_MODE_LABEL} should be 'UPDATE' when upgrading to a new version of the same major release but is set to '${IS_PIPELINE_MODE}'."
      fi

      # When first 5 digits of source are less than target then should be UPGRADE
      if [ "${CURRENT_VER:0:5}" -lt "${TARGET_VER:0:5}" ] && [ "${IS_PIPELINE_MODE}" != "UPGRADE" ]; then
        logError "213" "${IS_PIPELINE_MODE_LABEL} should be 'UPGRADE' but is set to '${IS_PIPELINE_MODE}'."
      fi


      # removed until I can figure out combos
      #+ CURRENT_VER=202330410400
      #+ TARGET_VER=202510110000
#      if [ "${CURRENT_VER:0:5}" -eq "${TARGET_VER:0:5}" ] && [ "${IS_DEPLOYMENT_MODE}" != "UPDATE" ]; then
#        logError "213" "DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}' but should be 'UPDATE' as the source and target have the same major versions."
#      fi
#      if [ "${CURRENT_VER:0:5}" -ne "${TARGET_VER:0:5}" ] && [ "${IS_DEPLOYMENT_MODE}" != "UPGRADE" ]; then
#        logError "213" "DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}' but should be 'UPGRADE' as the source and target have different major versions."
#      fi
#    fi

#    if [ "${IS_DEPLOYMENT_MODE}" == "UPGRADE" ] && [ "${IS_HELIX_FULL_STACK}" == "false" ]; then
#      logError "241" "HELIX_FULL_STACK_UPGRADE is not selected but is required when the DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}'."
#    fi

#    if [ "${IS_DEPLOYMENT_MODE}" == "UPDATE" ] && [ "${IS_HELIX_FULL_STACK}" == "true" ]; then
#      logError "242" "HELIX_FULL_STACK_UPGRADE is selected but this not valid when the DEPLOYMENT_MODE is '${IS_DEPLOYMENT_MODE}'."
    fi

    if [ "${IS_CUSTOM_BINARY_PATH}" == "true" ] && ! isJenkinsInCluster; then
      logWarning "008" "CUSTOM_BINARY_PATH option is selected - this is not usually required and may be a mistake."
    fi
    if [ "${IS_CUSTOM_BINARY_PATH}" == "true" ] && isJenkinsInCluster; then
      logError "263" "CUSTOM_BINARY_PATH option is selected - this is not supported when using a containerized Deployment Engine."
    fi

    if ! ${KUBECTL_BIN} config get-contexts "${IS_CLUSTER}" > /dev/null 2>&1; then
      logError "137" "The ${IS_CLUSTER_LABEL} value '${IS_CLUSTER}' is not a valid context in your kubeconfig file. Available contexts are:"
      ${KUBECTL_BIN} config get-contexts 2>/dev/null
    else
      if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" --context "${IS_CLUSTER}" get secret &> /dev/null ; then
        logError "251" "The ${IS_CLUSTER_LABEL} value '${IS_CLUSTER}' does not appear to have permissions for the '${IS_NAMESPACE}' namespace."
      else
        logMessage "${IS_CLUSTER_LABEL} '${IS_CLUSTER}' is a valid kubeconfig context." 1
      fi
    fi

    if [ "${IS_CLOUD}" == "true" ]; then
      logWarning "009" "IS_CLOUD option is selected - this will cause public cloud systems to provision an external load balancer."
    fi

    if [ "${IS_ROUTE_ENABLED}" == "true" ] || [ "${IS_ROUTE_TLS_ENABLED}" == "true" ]; then
      logWarning "010" "ROUTE_ENABLED and/or ROUTE_TLS_ENABLED are selected but should not be."
    fi

    if [ "${IS_IS_NAMESPACE}" != "${IS_NAMESPACE}" ]; then
      logError "138" "The IS_NAMESPACE value '${IS_IS_NAMESPACE}' does not match the IS_NAMESPACE defined in the hitt.conf file '${IS_NAMESPACE}'."
    else
      logMessage "IS_NAMESPACE is the expected value '${IS_NAMESPACE}'." 1
    fi

    if [ "${IS_VERSION}" -ge 2023303 ]; then
      IS_NS_MAX_LEN=23
    else
      IS_NS_MAX_LEN=33
    fi
    if [ "${#IS_IS_NAMESPACE}" -gt ${IS_NS_MAX_LEN} ]; then
      logError "139" "IS_NAMESPACE name is too long - maximum of ${IS_NS_MAX_LEN} characters."
    else
      logMessage "IS_NAMESPACE name length is ${IS_NS_MAX_LEN} characters or less." 1
    fi

    if [ "${ISP_CUSTOMER_SERVICE}-${ISP_ENVIRONMENT}" != "${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}" ]; then
      logError "140" "CUSTOMER_SERVICE '${ISP_CUSTOMER_SERVICE}' and/or ENVIRONMENT '${ISP_ENVIRONMENT}' values do not match those set in the hitt.conf file - '${IS_CUSTOMER_SERVICE}' and '${IS_ENVIRONMENT}'."
    else
      logMessage "CUSTOMER_SERVICE and ENVIRONMENT appear valid '${ISP_CUSTOMER_SERVICE} / ${ISP_ENVIRONMENT}'." 1
    fi

    if checkK8sAuth get ingressclasses; then
      if isBlank "${IS_INGRESS_CLASS}" || ! ${KUBECTL_BIN} get ingressclasses "${IS_INGRESS_CLASS}" > /dev/null 2>&1 ; then
        logError "141" "INGRESS_CLASS '${IS_INGRESS_CLASS}' is blank or not valid."
      else
        logMessage "INGRESS_CLASS '${IS_INGRESS_CLASS}' appears valid." 1
      fi
    else
      logWarning "011" "Unable to list ingressclasses - skipping INGRESS_CLASS checks."
    fi

    if [ "${IS_CLUSTER_DOMAIN}" != "" ]; then
      if [ "${IS_CLUSTER_DOMAIN}" != "${CLUSTER_DOMAIN}" ]; then
        logError "142" "The ${IS_CLUSTER_DOMAIN_LABEL} value '${IS_CLUSTER_DOMAIN}' does not match that used for the Helix Platform '${CLUSTER_DOMAIN}'."
      else
        logMessage "${IS_CLUSTER_DOMAIN_LABEL} is the expected value of '${CLUSTER_DOMAIN}'." 1
      fi
      if ! isRFC1123 "${IS_CLUSTER_DOMAIN}" ; then
        logError "258" "The ${IS_CLUSTER_DOMAIN_LABEL} value '${IS_CLUSTER_DOMAIN}' is not valid - it should only consist of lower case alphanumeric, '-' or '.' characters."
      fi
    else
      logError "131" "The ${IS_CLUSTER_DOMAIN_LABEL} value cannot be blank.  The expected value is '${CLUSTER_DOMAIN}'."
    fi

    if [ "${IS_INPUT_CONFIG_METHOD}" != "Generate_Input_File" ]; then
      logError "143" "INPUT_CONFIG_METHOD should be Generate_Input_File."
    else
      logMessage "INPUT_CONFIG_METHOD is the expected value of 'Generate_Input_File'." 1
    fi

    if isBlank "${IS_HELM_NODE}" ; then
      logError "144" "HELM_NODE is blank."
    else
      NODE_ARRAY=($(${CURL_BIN} -sk "${JENKINS_URL}/computer/api/json" | ${JQ_BIN} -r .computer[].displayName | grep -v Built ))
      NODE_MATCH=0
      for i in "${NODE_ARRAY[@]}"; do
        if [ "${IS_HELM_NODE}" == "${i}" ]; then NODE_MATCH=1; fi
      done
      if [ "${NODE_MATCH}" == 1"" ]; then
        logMessage "HELM_NODE '${IS_HELM_NODE}' is a valid node in Jenkins." 1
      else
        logError "145" "HELM_NODE '${IS_HELM_NODE}' not found as a Jenkins node.  Available nodes are:"
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

# Removed as not expected to be selected for pre-is
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
      logError "146" "REGISTRY_TYPE must be 'DTR' for onprem deployments. 'HARBOR' is only valid within BMC networks."
    else
      logMessage "REGISTRY_TYPE is the expected value of 'DTR'." 1
    fi

    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${HP_REGISTRY_SERVER}" ]; then
      logError "147" "HARBOR_REGISTRY_HOST '${IS_HARBOR_REGISTRY_HOST}' does not match the Helix Platform registry server '${HP_REGISTRY_SERVER}'."
    else
      logMessage "HARBOR_REGISTRY_HOST '${IS_HARBOR_REGISTRY_HOST}' matches the Helix Platform registry server '${HP_REGISTRY_SERVER}'." 1
    fi

    if [ "${IS_IMAGESECRET_NAME}" == "" ]; then
      logError "243" "IMAGESECRET_NAME is blank - you must provide a value for this parameter to be used as the registry credentials secret name."
    fi
    if [ "${IS_IMAGESECRET_NAME}" == "helix-es-secret" ]; then
      logError "252" "IMAGESECRET_NAME value of 'helix-es-secret' is not valid as it conflicts with a BMC secret name. Please change the value."
    fi

    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${HP_REGISTRY_USERNAME}" ]; then
      logError "148" "IMAGE_REGISTRY_USERNAME '${IS_IMAGE_REGISTRY_USERNAME}' does not match the Helix Platform registry username '${HP_REGISTRY_USERNAME}'."
    else
      logMessage "IMAGE_REGISTRY_USERNAME '${IS_IMAGE_REGISTRY_USERNAME}' matches the Helix Platform registry username '${HP_REGISTRY_USERNAME}'." 1
    fi

    if [ "${IS_DB_SSL_ENABLED}" == "true" ]; then
      logError "149" "DB_SSL_ENABLED should not be selected."
    fi

    if [ "${IS_DB_PORT}" == "" ]; then
        logError "240" "DB_PORT cannot be blank."
    else
      if ! [[ "${IS_DB_PORT}" =~ ^[0-9]+$ ]]; then
        logError "240" "DB_PORT value must be a number and not '${IS_DB_PORT}'."
      fi
    fi

    if [ "${IS_IS_DATABASE_ALWAYS_ON}" == "true" ]; then
      if [ "${IS_DB_TYPE}" != "mssql" ]; then
        logWarning "031" "IS_DATABASE_ALWAYS_ON is selected but this option is only valid for MSSQL databases and will be ignored."
      else
        logWarning "032" "IS_DATABASE_ALWAYS_ON is selected, please make sure you are using an MSSQL AlwaysOn database cluster and that the other DB details are set correctly."
      fi
    fi

    if [ "${IS_PIPELINE_MODE}" == "FRESH" ]; then
      if [ "${IS_DB_TYPE}" == "postgres" ]; then
        if [ "${IS_DATABASE_RESTORE}" == "false" ]; then
          logWarning "040" "DATABASE_RESTORE is not selected - please make sure you have restored the appropriate Postgres database dump."
        else
          logMessage "Postgres database dump will be restored by pipeline."
        fi
      else
          logMessage "Please make sure you have restored the appropriate ${IS_DB_TYPE^^} database dump."
      fi
    fi
#    else
#      logMessage "Postgres database dump will be restored."
#    fi

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

    if [ -n "${IS_DB_JDBC_URL}" ]; then
      if [ "${IS_DB_TYPE}" != "oracle" ]; then
        logError "217" "DB_JDBC_URL is only valid for Oracle databases - use with MSSQL/Postgres will cause a failure in the HELIX_SMARTAPPS_DEPLOY pipeline.  Please check with BMC Support."
      fi
      logWarning "047" "DB_JDBC_URL is set - make sure that the ONS port (6200) is open from the cluster to the DB server."
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

    if [ "$HELIX_LOGGING_DEPLOYED" == 1 ] && [ "${IS_LOGS_ELASTICSEARCH_HOSTNAME}" != "" ]; then
      if [ "${IS_LOGS_ELASTICSEARCH_TLS}" != "true" ]; then
        logError "151" "LOGS_ELASTICSEARCH_TLS '${IS_LOGS_ELASTICSEARCH_TLS}' is not the expected value of 'true'."
      else
        logMessage "LOGS_ELASTICSEARCH_TLS is the expected value of true." 1
      fi
      if [ "${IS_LOGS_ELASTICSEARCH_PASSWORD}" != "${HELIX_LOGGING_PASSWORD}" ]; then
        logError "152" "LOGS_ELASTICSEARCH_PASSWORD does not match the Helix Platform KIBANA_PASSWORD."
      else
        logMessage "LOGS_ELASTICSEARCH_PASSWORD matches the Helix Platform KIBANA_PASSWORD." 1
      fi
      checkIsValidElastic "${IS_LOGS_ELASTICSEARCH_HOSTNAME}" "LOGS_ELASTICSEARCH_HOSTNAME"
    fi

    if ! isRFC1123 "${IS_AR_SERVER_ALIAS}" ; then
      logError "258" "The AR_SERVER_ALIAS value '${IS_AR_SERVER_ALIAS}' is not valid - it should consist of lower case alphanumeric, '-' or '.' characters."
    fi

    if [ "${IS_PLATFORM_INT}" == "1" ] ; then
      if [ "${IS_ENABLE_PLATFORM_INT_NORMALIZATION}" == "false" ] && [ "${IS_VERSION}" -lt 2023303 ]; then
        logWarning "007" "platform-int pods are enabled but ENABLE_PLATFORM_INT_NORMALIZATION is not selected."
      fi
      if [ "${IS_ENABLE_PLATFORM_INT_NORMALIZATION}" == "true" ] && [ "${IS_VERSION}" -ge 2023303 ]; then
        logWarning "033" "ENABLE_PLATFORM_INT_NORMALIZATION is selected but will be ignored."
      fi
    fi

    if [ "${IS_IMAGE_REGISTRY_PASSWORD}" != "${HP_REGISTRY_PASSWORD}" ]; then
      logError "153" "IMAGE_REGISTRY_PASSWORD does not match the Helix Platform registry password."
    else
      logMessage "IMAGE_REGISTRY_PASSWORD matches the Helix Platform registry password." 1
    fi

    if [ "$IS_VC_RKM_USER_NAME" == "${IS_VC_PROXY_USER_LOGIN_NAME}" ] || [ -z "$IS_VC_RKM_USER_NAME" ] || [ -z "${IS_VC_PROXY_USER_LOGIN_NAME}" ]; then
      logError "154" "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME must be different and cannot be blank."
    else
      logMessage "VC_RKM_USER_NAME and VC_PROXY_USER_LOGIN_NAME appear valid." 1
    fi

    if [ -n "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" ] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ ^\[.* ]] && [[ ! "${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}" =~ .*\]$ ]]; then
      logError "155" "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS '${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}' does not match the expected format of [x.x.x.x] - missing square brackets?"
    else
      logMessage "PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS is blank or matches the expected format - '${IS_PLATFORM_ADMIN_PLATFORM_EXTERNAL_IPS}'." 1
    fi

    if [ "${IS_RSSO_ADMIN_USER,,}" != "${RSSO_USERNAME,,}" ]; then
      logError "156" "RSSO_ADMIN_USER '${IS_RSSO_ADMIN_USER}' does not match the Helix Platform RSSO_ADMIN_USER '${RSSO_USERNAME}'."
    else
      logMessage "RSSO_ADMIN_USER is the expected value of '${IS_RSSO_ADMIN_USER}'." 1
    fi

    if [ "${IS_RSSO_ADMIN_PASSWORD}" != "${RSSO_PASSWORD}" ]; then
      logError "250" "RSSO_ADMIN_PASSWORD does not match the Helix Platform RSSO password."
    else
      logMessage "RSSO_ADMIN_PASSWORD is the expected value." 1
    fi

    if [ "${IS_HELIX_PLATFORM_NAMESPACE}" != "${HP_NAMESPACE}" ]; then
      logError "157" "HELIX_PLATFORM_NAMESPACE '${IS_HELIX_PLATFORM_NAMESPACE}' is not the expected value of '${HP_NAMESPACE}'."
    else
      logMessage "HELIX_PLATFORM_NAMESPACE is the expected value of '${HP_NAMESPACE}'." 1
    fi

    if [ "${IS_HELIX_PLATFORM_CUSTOMER_NAME}" != "${HP_COMPANY_NAME}" ] && [ "${SM_PLATFORM_CORE}" == "no" ]; then
      logError "158" "HELIX_PLATFORM_CUSTOMER_NAME '${IS_HELIX_PLATFORM_CUSTOMER_NAME}' is not the expected value of '${HP_COMPANY_NAME}'."
    else
      logMessage "HELIX_PLATFORM_CUSTOMER_NAME is the expected value of '${HP_COMPANY_NAME}'." 1
    fi
  fi
}

getCacertsFile() {
  SKIP_CACERTS=1
  if [ "${1}" == "IS" ]; then
    if [[ "${MODE}" == "fix" ]] && [[ -f "${CACERTS_FILENAME}" ]]; then
      SKIP_CACERTS=0
      logMessage "Using cacerts file '${CACERTS_FILENAME}'." 1
      return
    fi
    if [ "${MODE}" == "pre-is" ]; then
      if [ -f configsrepo/customer/customCerts/cacerts ] ; then
        SKIP_CACERTS=0
        cp -f configsrepo/customer/customCerts/cacerts ${CACERTS_FILENAME}
        logMessage "Using cacerts file from CUSTOMER_CONFIGS repo."
        return
      else
        logWarning "017" "Custom cacerts file not found - remember to attach when building the HELIX_ONPREM_DEPLOYMENT pipeline unless using a Digicert certificate."
      fi
      if [ -f itsmrepo/pipeline/tasks/cacerts ] ; then
        SKIP_CACERTS=0
        cp -f itsmrepo/pipeline/tasks/cacerts ${CACERTS_FILENAME}
        logMessage "Using cacerts file from ITSM_REPO."
        return
      fi
    fi

    if [ "${MODE}" == "post-is" ]; then
      logMessage "Extracting cacerts file from Helix IS cacerts secret..." 1
      if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts > /dev/null 2>&1; then
        logError "159" "'cacerts' secret not found in Helix IS namespace."
        return
      fi
      IS_CACERTS_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts -o json)
      IS_CACERTS=$(echo "${IS_CACERTS_JSON}" | ${JQ_BIN} -r '.data.cacerts')
      if [ "${IS_CACERTS}" == "null" ]; then
        logError "160" "Required file 'cacerts' not found in the cacerts secret. File(s) in the secret are:"
        echo "${IS_CACERTS_JSON}" | ${JQ_BIN} '.data | keys'
      else
        SKIP_CACERTS=0
        echo "${IS_CACERTS}" | ${BASE64_BIN} -d > "${CACERTS_FILENAME}"
      fi
    fi
  fi

  if [ "${1}" == "HP" ]; then
    logMessage "Extracting cacerts file from Helix Platform cacertcm configMap..." 1
    if ! ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm cacertcm > /dev/null 2>&1; then
      logError "159" "'cacertcm' configMap not found in Helix Platform namespace."
      return
    fi
    HP_CACERTS_JSON=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm cacertcm -o json)
    HP_CACERTS=$(echo "${HP_CACERTS_JSON}" | ${JQ_BIN} -r '.binaryData.cacerts')
    if [ "${HP_CACERTS}" == "null" ]; then
      logError "160" "Required file 'cacerts' not found in the cacertcm configMap. File(s) in the configMap are:"
      echo "${HP_CACERTS_JSON}" | ${JQ_BIN} '.data | keys'
    else
      SKIP_CACERTS=0
      echo "${HP_CACERTS}" | ${BASE64_BIN} -d > "${CACERTS_FILENAME}"
    fi
  fi
}

validateCacertsFile() {
#  if [ "${SKIP_REPO}" == "1" ]; then
#    logMessage "CUSTOMER_CONFIGS repo not available - skipping checks."
#    return
#  fi
  VALID_CACERTS=0
  case "${1}" in
    IS)
      CACERTS_SOURCE="Service Management"
      CACERTS_FILENAME=is-sealcacerts
      ;;
    HP)
      CACERTS_SOURCE="Helix Platform"
      CACERTS_FILENAME=hp-sealcacerts
      IS_CACERTS_SSL_TRUSTSTORE_PASSWORD="changeit"
      ;;
    *)
      VALID_CACERTS=1
      SKIP_CACERTS=1
      return
      ;;
  esac
  getCacertsFile ${1}
  if [ "${SKIP_CACERTS}" == "1" ]; then
    logWarning "046" "${CACERTS_SOURCE} cacerts file not found - skipping checks."
    VALID_CACERTS=1
    return
  fi
  CACERTS_FILETYPE=$(file "${CACERTS_FILENAME}" | cut -f 2- -d ' ')
  if [ "${CACERTS_FILETYPE,,}" != "java keystore" ]; then
    logError "161" "${CACERTS_SOURCE} cacerts file is of type '${CACERTS_FILETYPE}' and not the expected Java keystore."
    VALID_CACERTS=1
    SKIP_CLEANUP=1
    return
  else
    logMessage "${CACERTS_SOURCE} cacerts file is a valid Java keystore." 1
  fi

  logMessage "Validating cacerts..."
  # Convert JKS to pem
  #  ${KEYTOOL_BIN} -importkeystore -srckeystore ${CACERTS_FILENAME} -destkeystore sealstore.p12 -srcstoretype jks -deststoretype pkcs12 -srcstorepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -deststorepass changeit > /dev/null 2>&1
  #  ${OPENSSL_BIN} pkcs12 -in sealstore.p12 -out sealstore.pem -password pass:"${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" > /dev/null 2>&1
  #  if ! ${CURL_BIN} -s "${RSSO_URL}" --cacert sealstore.pem > /dev/null 2>&1 ; then
  unpackSSLPoke

  if [ "${1}" == "IS" ]; then
    if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
      IS_CACERTS_SSL_TRUSTSTORE_PASSWORD="changeit"
    fi

    if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" != "changeit" ]; then
      logMessage "CACERTS_SSL_TRUSTSTORE_PASSWORD is set - using non-default password for cacerts." 1
      if ! ${KEYTOOL_BIN} -list -keystore ${CACERTS_FILENAME} -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" > /dev/null 2>&1 ; then
        logError "214" "The value of CACERTS_SSL_TRUSTSTORE_PASSWORD is not set to the correct password for the cacerts file."
        return
      fi
    fi

    if ! ${KEYTOOL_BIN} -list -keystore ${CACERTS_FILENAME} -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -alias "${FTS_ELASTIC_CERTNAME}" > /dev/null 2>&1 ; then
      logError "162" "cacerts file does not contain the expected '${FTS_ELASTIC_CERTNAME}' certificate required for FTS Elasticsearch connection."
      VALID_CACERTS=1
    else
      logMessage "cacerts file contains the expected Elasticsearch '${FTS_ELASTIC_CERTNAME}' certificate." 1
    fi

    if ! ${JAVA_BIN} "-Djavax.net.ssl.trustStore=${CACERTS_FILENAME}" "-Djavax.net.ssl.trustStorePassword=${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" ${JAVA_PROXY_STRING} SSLPoke "${LB_HOST}" 443 >>${HITT_ERR_FILE} 2>&1 ; then
      logError "163" "cacerts file does not appear to contain the certificates required to connect to the Helix Platform LB_HOST."
      VALID_CACERTS=1
    fi
  fi

  for i in "${IS_ALIAS_SUFFIXES[@]}"; do
    TARGET="${IS_ALIAS_PREFIX}-${i}.${CLUSTER_DOMAIN}"
#    if ! ${CURL_BIN} -s "https://${TARGET}" --cacert sealstore.pem > /dev/null 2>&1; then
    if ! ${JAVA_BIN} "-Djavax.net.ssl.trustStore=${CACERTS_FILENAME}" "-Djavax.net.ssl.trustStorePassword=${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" ${JAVA_PROXY_STRING} SSLPoke "${TARGET}" 443 >>${HITT_ERR_FILE} 2>&1 ; then
      if echo "${TARGET}" | grep -q reporting ; then
        MSG_SUFFIX="Note: only required for ITSM 25.3.01 and later."
      fi
      logError "164" "Certificate for '${TARGET}' not found in ${CACERTS_SOURCE} cacerts. ${MSG_SUFFIX}"
      MSG_SUFFIX=""
      VALID_CACERTS=1
    else
      logMessage "  - valid certificate for '${TARGET}' found in ${CACERTS_SOURCE} cacerts file." 1
    fi
  done

  if [ "${VALID_CACERTS}" == 0 ]; then
    logMessage "${CACERTS_SOURCE} cacerts file appears valid." 1
  else
    SKIP_CLEANUP=1
  fi
}

checkISFTSElasticHost() {
  # IP/service.ns pipeline_param_name
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "165" "FTS_ELASTICSEARCH_HOSTNAME IP address '${1}' not found as an externalIP for any exposed service in the Helix Platform namespace."
    else
      logWarning "018" "Recommend using 'servicename.namespace' format instead of an exposed IP address for FTS_ELASTICSEARCH_HOSTNAME."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u "${LOG_ELASTICSEARCH_USERNAME}:${LOG_ELASTICSEARCH_PASSWORD}" -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "166" "${1} does not appear to be a valid Elasticsearch server IP address."
      else
        if ! echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name' | grep -q 'logs$' ; then
          logError "167" "'${1}' does not appear to be the expected Elasticsearch service instance for FTS."
          echo "${ES_HEALTH}" | ${JQ_BIN} -r '.cluster_name'
        else
          logMessage "'${1}' appears to be a valid Elasticsearch service instance for FTS." 1
        fi
      fi
    fi
  else
    if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
      logError "168" "FTS_ELASTICSEARCH_HOSTNAME service name '${1}' is not the expected value of '${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}'."
    else
      logMessage "FTS_ELASTICSEARCH_HOSTNAME appears valid '${1}'." 1
    fi
  fi
}

checkIsValidElastic() {
  BAD_ELASTIC=0
  if [ $(isIPAddress "${1}") == "0" ]; then
    if [ $(getSvcFromExternalIP "${1}") == "1" ]; then
      logError "169" "${2} IP address '${1}' not found as an externalIP for any exposed service in the Helix Platform namespace."
      return
    else
      logWarning "019" "Recommend using 'servicename.namespace' format instead of an exposed IP address for ${2}."
      # Try and confirm IP is a valid ES
      ES_HEALTH=$(${CURL_BIN} -sk -u "${3}:${4}" -X GET https://"${1}":9200/_cluster/health)
      if [ -z "${ES_HEALTH}" ]; then
        logError "170" "'${1}' does not appear to be a valid Elasticsearch server IP address."
        return
      fi
    fi
  else
    case "${2}" in
      FTS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}" ]; then
          logError "168" "FTS_ELASTICSEARCH_HOSTNAME service name '${1}' is not the expected value of '${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}'."
        fi
        ;;
      LOGS_ELASTICSEARCH_HOSTNAME)
        if [ "${1}" != "${EFK_ELASTIC_SERVICENAME}.${HELIX_LOGGING_NAMESPACE}" ]; then
          logError "172" "LOGS_ELASTICSEARCH_HOSTNAME service name '${1}' is not the expected value of '${EFK_ELASTIC_SERVICENAME}.${HELIX_LOGGING_NAMESPACE}'."
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
  logMessage "FTS_ELASTICSEARCH_USERNAME is '${IS_FTS_ELASTICSEARCH_USERNAME}'." 1
  if [ "${IS_FTS_ELASTICSEARCH_PORT}" != "9200" ]; then
    logError "173" "FTS_ELASTICSEARCH_PORT '${IS_FTS_ELASTICSEARCH_PORT}' is not the expected value of 9200."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_PORT is the expected value of '9200'." 1
  fi

  if [ "${IS_FTS_ELASTICSEARCH_SECURE}" != "true" ]; then
    logError "174" "FTS_ELASTICSEARCH_SECURE '${IS_FTS_ELASTICSEARCH_SECURE}' is not the expected value of 'true'."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_SECURE is the expected value of 'true'." 1
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
    logError "175" "FTS_ELASTICSEARCH_USER_PASSWORD is not the expected value of '${LOG_ELASTICSEARCH_PASSWORD}'."
    BAD_FTS_ELASTIC=1
  else
    logMessage "FTS_ELASTICSEARCH_USER_PASSWORD is the expected value." 1
  fi

  [[ "${BAD_FTS_ELASTIC}" == "0" ]] && checkIsValidElastic "${IS_FTS_ELASTICSEARCH_HOSTNAME}" "FTS_ELASTICSEARCH_HOSTNAME" "${IS_FTS_ELASTICSEARCH_USERNAME}" "${IS_FTS_ELASTICSEARCH_USER_PASSWORD}"

}

checkISRESTReady() {
  IS_REST_READY=0
  if ! IS_INT_ROLE=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get svc platform-int -o jsonpath='{.spec.selector.role}' 2>/dev/null); then
    logMessage "IS platform pods not found - skipping checks."
    return
  fi
  if ! IS_RESTAPI_POD_STATUS=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get pod "platform-${IS_INT_ROLE}-0" -o jsonpath='{.status.containerStatuses[?(@.name=="platform")].ready}'); then
    logMessage "IS platform-${IS_INT_ROLE}-0 pod not found - skipping checks."
    return
  fi
  if [ "${IS_RESTAPI_POD_STATUS}" == "false" ]; then
    logMessage "IS platform-${IS_INT_ROLE}-0 pod not ready - skipping checks."
    return
  fi
  getISAdminCreds
  if ! getISJWT; then
    logError "176" "Failed to authenticate user '${IS_USER}' - skipping checks."
    return
  fi
  IS_REST_READY=1
}

checkISLicenseStatus() {
  if [ "${IS_REST_READY}" == "0" ]; then
    return
  fi
  logMessage "Checking IS license status..."
  checkISLicense
}

checkISTenant() {
  if [ "${IS_REST_READY}" == "0" ]; then
    return
  fi
  logMessage "Checking IS Tenant..."
  getISTenant
  logMessage "IS tenant name: '${IS_TENANT_NAME}', domainIdentifier: '${IS_TENANT_DOMID}', virtualHostname: '${IS_TENANT_VHOSTNAME}'." 1
  return # skipping following as still under review
  if [ "${IS_TENANT_NAME}" != "${IS_CUSTOMER_SERVICE}" ]; then
    logError "xxx" "IS tenant name is '${IS_TENANT_NAME}' and not the expected '${IS_CUSTOMER_SERVICE}'."
  fi
  if [ "${IS_TENANT_DOMID}" != "${HP_TENANT}" ]; then
    logError "xxx" "IS tenant domainIdentifier is '${IS_TENANT_DOMID}' and not the expected '${HP_TENANT}'."
  fi
  if [ "${IS_TENANT_VHOSTNAME}" != "${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}" ]; then
    logError "xxx" "IS tenant virtualHostname is '${IS_TENANT_VHOSTNAME}' and not the expected '${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}'."
  fi
}

getISTenant() {
  IS_TENANT_JSON=$(${CURL_BIN} -sk -X GET "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/rx/application/datapage?dataPageType=com.bmc.arsys.rx.application.tenant.datapage.TenantDataPageQuery&pageSize=50&startIndex=0&shouldIncludeTotalSize=false&propertySelection=name%2CdomainIdentifier%2CvirtualHostname" -H "Authorization: AR-JWT ${ARJWT}")
  IS_TENANT_NAME=$(echo "${IS_TENANT_JSON}" | ${JQ_BIN} -r '.data[].name')
  IS_TENANT_DOMID=$(echo "${IS_TENANT_JSON}" | ${JQ_BIN} -r '.data[].domainIdentifier')
  IS_TENANT_VHOSTNAME=$(echo "${IS_TENANT_JSON}" | ${JQ_BIN} -r '.data[].virtualHostname')
}

getISJWT() {
  # Use --data-urlencode so passwords with %, &, +, etc. are not mangled by curl's -d percent-decoding.
  ARJWT=$(${CURL_BIN} -sk -X POST "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/jwt/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=${IS_USER}" \
    --data-urlencode "password=${IS_PASSWD}")
  if echo "${ARJWT}" | grep -q "ERROR"; then
    return 1
  else
    return 0
  fi
}

getISServerInfo() {
  # $1 is key to return
  if [ -z "${IS_SERVER_INFO}" ]; then
    IS_SERVER_INFO=$(${CURL_BIN} -sk "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/arsys/v1/entry/AR%20System%20Administration%3A%20Server%20Information?q=%27configurationName%27%3D%22%25%22" -H "Authorization: AR-JWT ${ARJWT}")
  fi
  echo "${IS_SERVER_INFO}" | ${JQ_BIN} -r ".entries[0].values.${1}"
}

checkISLicense() {
  IS_LICENSE_TYPE=$(getISServerInfo licensetype)
  if [ "${IS_LICENSE_TYPE}" != "AR Server" ]; then
    logWarning "020" "IS Server does not have a permanent license - current license type is ${IS_LICENSE_TYPE}."
  else
    logMessage "IS Server is licensed."
  fi
}

getISAdminCreds() {
  IS_USER=hannah_admin
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret ar-global-secret > /dev/null 2>&1; then
    IS_PASSWD=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret ar-global-secret -o jsonpath='{.data.ATWS_UDDI_ADMIN_PASSWORD}' | ${BASE64_BIN} -d )
  else
    IS_PASSWD=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret atriumwebsvc -o jsonpath='{.data.UDDI_ADMIN_PASSWORD}' | ${BASE64_BIN} -d )
  fi
}

checkAssistTool() {
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get deployment assisttool-dep > /dev/null 2>&1 ; then
    SAT_DEPLOYED=1
    logMessage "Support Assistant Tool found - checking for fpackager sidecar containers..." 1
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.spec.template.spec.containers[*].name}' | grep -q fpackager ; then
      logError "177" "fpackager sidecar containers not found - Support Assistant will not be able to access application logs."
    else
      logMessage "fpackager sidecar containers are present." 1
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get role assisttool-rl > /dev/null 2>&1 ; then
      logError "178" "assisttool-rl role not found - Support Assistant will not be able to access application logs."
    else
      logMessage "assisttool-rl role present in Helix IS namespace." 1
    fi
    if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get rolebinding assisttool-rlb > /dev/null 2>&1 ; then
      logError "178" "assisttool-rlb rolebinding not found - Support Assistant will not be able to access application logs."
    else
      logMessage "assisttool-rlb rolebinding present in Helix IS namespace." 1
    fi
  else
    logMessage "Support Assistant Tool is not deployed." 1
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
      JISQLURL=jdbc:postgresql://${IS_DATABASE_HOST_NAME}:${IS_DB_PORT}/${JISQL_DB_NAME}
      JISQLDRIVER=postgresql
      ;;
  esac
  JISQLCMD="${JAVA_BIN} -cp ./jisql.jar:./${JISQLJAR} com.xigole.util.sql.Jisql -user ${JISQL_USERNAME} -password ${JISQL_PASSWORD} -driver ${JISQLDRIVER} -cstring ${JISQLURL} -noheader -query"
}

testNetConnection () {
  # Try to open the connection; exit code 0 if success, non-zero if fail
  (echo > /dev/tcp/"${1}"/"${2}") >/dev/null 2>&1
}

checkISDBSettings() {
  if ! testNetConnection "${IS_DATABASE_HOST_NAME}" "${IS_DB_PORT}"; then
    logWarning "027" "IS DB server '${IS_DATABASE_HOST_NAME}' is not reachable on port '${IS_DB_PORT}' - this is expected if there is no connectivity from this system - skipping DB checks."
    SKIP_DB_CHECKS=1
    return
  else
    logMessage "IS DB server '${IS_DATABASE_HOST_NAME}' is reachable on port '${IS_DB_PORT}'." 1
  fi
  if [ -z "${IS_AR_DB_USER}" ] || [ -z "${IS_AR_DB_PASSWORD}" ]; then
    logError "246" "AR_DB_USER and/or AR_DB_PASSWORD are blank - skipping checks."
    SKIP_AR_DB_CHECKS=1
  fi
  JISQL_USERNAME="${IS_AR_DB_USER}"
  JISQL_PASSWORD="${IS_AR_DB_PASSWORD}"
  JISQL_DB_NAME="${IS_AR_DB_NAME}"
  if [ "${IS_DATABASE_RESTORE}" == "true" ] && [ "${IS_DB_TYPE}" == "postgres" ]; then
    if [ -z "${IS_DATABASE_ADMIN_USER}" ] || [ -z "${IS_DATABASE_ADMIN_PASSWORD}" ]; then
      logError "246" "DATABASE_ADMIN_USER and/or DATABASE_ADMIN_PASSWORD are blank - skipping checks."
      SKIP_AR_DB_CHECKS=1
    fi
    JISQL_USERNAME="${IS_DATABASE_ADMIN_USER}"
    JISQL_PASSWORD="${IS_DATABASE_ADMIN_PASSWORD}"
    JISQL_DB_NAME="postgres"
  fi
  [[ -n "${SKIP_AR_DB_CHECKS}" ]] && return
  if [ -f dbjars.tgz ]; then
    logMessage "Found dbjars.tgz - running DB checks." 1
    logMessage "Unpacking dbjars.tgz..." 1
    ${TAR_BIN} zxf dbjars.tgz
    buildJISQLcmd
    logMessage "Connecting to '${JISQLURL}' as '${JISQL_USERNAME}'..." 1
    # Note - new line is needed to avoid Java heap errors from jisql
    if [ "${IS_DB_TYPE}" == "postgres" ] && [ "${IS_DATABASE_RESTORE}" == "true" ]; then
      SQL_RESULT=$($JISQLCMD "select 1
    go" 2>&1)
    else
      SQL_RESULT=$($JISQLCMD "select currDbVersion from control
    go" 2>&1)
    fi

    if echo "${SQL_RESULT}" | grep -q ErrorCode ; then
     logError "180" "Problem connecting to database - please review the following message."
     echo "${SQL_RESULT}"
     return
    else
      DB_VERSION=$(echo "${SQL_RESULT}" | awk '{print $1}')
      if [ ! -z "${IS_DB_VERSION}" ]; then
        if [ "${DB_VERSION}" != "${IS_DB_VERSION}" ] && [ "${DB_VERSION}" != "1" ]; then
          logError "181" "Database is not the expected version - found '${DB_VERSION}' but expected '${IS_DB_VERSION}'.  This is expected when running an upgrade."
        else
          if [ "${DB_VERSION}" != "1" ]; then
            logMessage "Database is the expected version - '${DB_VERSION}'." 1
          else
            logMessage "DATABASE_RESTORE selected so skipping currDbVersion check." 1
          fi
        fi
      else
        logMessage "Database currDbVersion is '${DB_VERSION}'." 1
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

isRFC1123() {
  local INPUT="$1"
  local LABEL_REGEX='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'

  # Reject empty input, leading/trailing/consecutive dots
  [[ "$INPUT" =~ ^\. ]] && return 1
  [[ "$INPUT" =~ \.$ ]] && return 1
  [[ "$INPUT" =~ \.\. ]] && return 1

  IFS='.' read -ra LABELS <<< "$INPUT"
  for LABEL in "${LABELS[@]}"; do
      [[ "${LABEL}" =~ $LABEL_REGEX ]] || return 1
  done
  return 0
}

reportResults() {
  echo ""
  logStatus "HITT Summary Report"
  echo "==================="
  if [ $FAIL -gt 0 ] || [ $WARN -gt 0 ] ; then
#    echo -e "${BOLD}${FAIL} errors / ${WARN} warnings found - please review the ${HITT_MSG_FILE} file for more details and suggested fixes.${NORMAL}"
#    echo ""
    if [ "${#ERROR_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${RED}ERRORS:${NORMAL}"
      printf '%s\n' "${ERROR_ARRAY[@]}"
    fi
    if [ "${#WARN_ARRAY[@]}" != "0" ]; then
      echo -e "${BOLD}${YELLOW}WARNINGS:${NORMAL}"
      printf '%s\n' "${WARN_ARRAY[@]}"
    fi
    echo "==================="
    echo -e "${BOLD}Please review the ${GREEN}${HITT_MSG_FILE}${NORMAL}${BOLD} file or run 'bash $0 -e MSG_NUM' for explanations and suggested fixes for the messages above.${NORMAL}"
    echo -e "${BOLD}Attach the ${YELLOW}hittlogs.zip${NORMAL}${BOLD} file to your case if requested by BMC Support.${NORMAL}"
  else
    echo -e "${BOLD}Tests complete - no errors or warnings found.${NORMAL}"
  fi
}

checkKubeconfig() {
  KUBECONFIG_ERROR=0
  if [ ! -f ~/.kube/config ]; then
    logError "186" "Default KUBECONFIG file '~/.kube/config' required by Jenkins pipelines not found."
    KUBECONFIG_ERROR=1
  fi
  if ! ${KUBECTL_BIN} version > /dev/null 2>&1; then
    logError "184" "'kubectl version' command returned an error - unable to continue." 1
  fi
  if [ ! -z "${KUBECONFIG}" ] && [ "${KUBECONFIG}" != "${HOME}/.kube/config" ]; then
    if [ "${MODE}" == "info" ]; then return; fi
    logError "185" "KUBECONFIG environment variable is set '${KUBECONFIG}' but is not the default of '${HOME}/.kube/config' required by Jenkins."
    KUBECONFIG_ERROR=1
  fi
  if [ ${KUBECONFIG_ERROR} == "0" ]; then
    logMessage "Local KUBECONFIG file appears valid." 1
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
  IMAGESECRET_JSON=$(${KUBECTL_BIN} -n "${1}" get secret "${2}" -o jsonpath='{.data.\.dockerconfigjson}' 2>/dev/null | ${BASE64_BIN} -d)
  if [ "${IMAGESECRET_JSON}" = "" ]; then
    logError "187" "Failed to get registry details from '${2}' secret in '${1}' namespace."
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
  logMessage "Helix Platform IMAGE_REGISTRY_HOST is '${HP_REGISTRY_SERVER}' and IMAGE_REGISTRY_USERNAME is '${HP_REGISTRY_USERNAME}'." 1
}

checkISDBLatency() {
  if [ "${IS_DATABASE_HOST_NAME}" == "" ]; then
    logMessage "DATABASE_HOST_NAME not set - can't test IS DB latency."
    return
  fi
  logMessage "Attempting to test latency between cluster and IS DB server '${IS_DATABASE_HOST_NAME}'..."
  PING_NAMESPACE="${HP_NAMESPACE}"
  PING_SELECTOR="data=postgres"
  if [ "${MODE}" == "post-is" ]; then
    PING_NAMESPACE="${IS_NAMESPACE}"
    PING_SELECTOR="app=platform-fts"
  fi
  PING_POD=$(${KUBECTL_BIN} -n "${PING_NAMESPACE}" get pod --no-headers -l "${PING_SELECTOR}" -o custom-columns=:metadata.name --field-selector status.phase=Running | head -1)
  if [ -n "${PING_POD}" ]; then
    PING_RESULT=$(${KUBECTL_BIN} -n "${PING_NAMESPACE}" exec -i "${PING_POD}" -- env IS_DATABASE_HOST_NAME="${IS_DATABASE_HOST_NAME}" IS_DB_PORT="${IS_DB_PORT}"  bash -s 2> >(grep -v 'Defaulted container') <<'EOF'
      total_ms=0
      count=0
      if timeout 2 bash -c "</dev/tcp/${IS_DATABASE_HOST_NAME}/${IS_DB_PORT}" 2>/dev/null; then
        # Average bash startup overhead over 3 samples for a more stable baseline
        overhead_total=0
        for o in {1..3}; do
          os=$( (time bash -c exit) 2>&1 | grep real | sed -E 's/real[[:space:]]+([0-9]+)m([0-9]+\.[0-9]+)s/\1 \2/')
          om=${os%% *}
          of=${os##* }
          of=$(printf "%-3s" "${of#*.}" | tr ' ' '0')
          overhead_total=$(( overhead_total + om * 60000 + 10#$of ))
        done
        overhead_ms=$(( overhead_total / 3 ))
        for i in {1..10}; do
          sec=$( (time timeout 2 bash -c "</dev/tcp/${IS_DATABASE_HOST_NAME}/${IS_DB_PORT}") 2>&1 | grep real | sed -E 's/real[[:space:]]+([0-9]+)m([0-9]+\.[0-9]+)s/\1 \2/')
          [ -z "$sec" ] && continue
          m=${sec%% *}
          f=${sec##* }
          f=$(printf "%-3s" "${f#*.}" | tr ' ' '0')
          ms=$(( m * 60000 + 10#$f ))
          adj_ms=$(( ms > overhead_ms ? ms - overhead_ms : 0 ))
          total_ms=$(( total_ms + adj_ms ))
          count=$(( count + 1 ))
        done
        if [ "$count" -gt 0 ]; then
          echo $(( total_ms / count ))
        else
          echo "FAILED"
        fi
      else
        echo "FAILED"
      fi
EOF
    )
    if [ "${PING_RESULT}" != "FAILED" ]; then
      IS_DB_LATENCY="${PING_RESULT}"
      logMessage "IS DB latency from ${PING_NAMESPACE}/${PING_POD} is ${IS_DB_LATENCY}ms."
      if compare "${IS_DB_LATENCY} <= 1" ; then logMessage "Latency is ${BOLD}GOOD${NORMAL}." ; return ; fi
      if compare "${IS_DB_LATENCY} <= 3" ; then logMessage "Latency is ${BOLD}AVERAGE${NORMAL}." ; return ; fi
      if compare "${IS_DB_LATENCY} <= 6" ; then logMessage "Latency is ${BOLD}POOR${NORMAL}. Performance may be impacted." ; return ; fi
      if compare "${IS_DB_LATENCY} > 6" ; then logMessage "Latency is ${BOLD}VERY POOR${NORMAL}. Performance will be impacted." ; return ; fi
    else
      logError "188" "Unexpected response from IS DB latency test.  Is the DATABASE_HOST_NAME '${IS_DATABASE_HOST_NAME}' accessible from the '${PING_NAMESPACE}/${PING_POD}' pod?"
    fi
  else
    logError "188" "No running pod found with selector '${PING_SELECTOR}' in namespace '${PING_NAMESPACE}' - cannot test IS DB latency."
  fi
}

checkISDockerLogin() {
  SKIP_REGISTRY=0
  IS_HARBOR_REGISTRY_HOSTNAME=$(echo "${IS_HARBOR_REGISTRY_HOST%%/*}")
  getRegistryDetailsFromIS
  if [ "${MODE}" == "post-is" ]; then
    if [ "${SKIP_REGISTRY}" == "1" ]; then
      logError "189" "Failed to get IS registry details - skipping checks."
      return
    fi
    IS_HARBOR_REGISTRY_HOSTNAME=$(echo "${IS_SECRET_HARBOR_REGISTRY_HOST%%/*}")
  fi

  if [ "${MODE}" == "pre-is" ] && [ "${SKIP_REGISTRY}" == "0" ]; then
    if [ "${IS_HARBOR_REGISTRY_HOST}" != "${IS_SECRET_HARBOR_REGISTRY_HOST}" ]; then
      logError "190" "HARBOR_REGISTRY_HOST '${IS_HARBOR_REGISTRY_HOST}' does not match the value in the registry secret '${IS_SECRET_HARBOR_REGISTRY_HOST}'."
    fi
    if [ "${IS_IMAGE_REGISTRY_USERNAME}" != "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" ]; then
      logError "190" "IMAGE_REGISTRY_USERNAME '${IS_IMAGE_REGISTRY_USERNAME}' does not match the value in the registry secret '${IS_SECRET_IMAGE_REGISTRY_USERNAME}'."
    fi
  fi



  if ! docker ps > /dev/null 2>&1; then
    if ! which docker > /dev/null 2>&1 ; then
      LOG_MSG="'docker' command not found in path"
    else
      LOG_MSG="'docker ps' command returned an error"
    fi
    logWarning "022" "${LOG_MSG} - skipping registry credentials check."
    return
  fi
  if docker login "${IS_SECRET_HARBOR_REGISTRY_HOST}" -u "${IS_SECRET_IMAGE_REGISTRY_USERNAME}" -p "${IS_SECRET_IMAGE_REGISTRY_PASSWORD}" > /dev/null 2>&1 ; then
    logMessage "IMAGE_REGISTRY credentials are valid - docker login to '${IS_SECRET_HARBOR_REGISTRY_HOST}' was successful." 1
  else
    logError "192" "'docker login' to '${IS_SECRET_HARBOR_REGISTRY_HOST}' failed - please check credentials."
  fi
}

dumpVARs() {
  [[ ${CREATE_LOGS} -eq 0 ]] && return
  rm -f "${VALUES_LOG_FILE}" "${VALUES_JSON_FILE}"
  # Debug mode to print all variables
  if [ "${MODE}" == "pre-is" ]; then
    echo "CUSTOMER_SERVICE=${ISP_CUSTOMER_SERVICE}" >> "${VALUES_LOG_FILE}"
    echo "ENVIRONMENT=${ISP_ENVIRONMENT}" >> "${VALUES_LOG_FILE}"
    echo "FTS_ELASTICSEARCH_USERNAME=${IS_FTS_ELASTICSEARCH_USERNAME}" >> "${VALUES_LOG_FILE}"
    for i in "${PIPELINE_VARS[@]}"; do
      if [ "${LOG_PASSWDS}" == "0" ] && [[ "${i}" =~ "PASSWORD" ]]; then
        continue
      fi
      v="IS_${i}"
      echo "${i}=${!v}" >> "${VALUES_LOG_FILE}"
    done
    #if [ "${LOG_PASSWDS}" == "1" ]; then
    #  echo "${PASSWDS_JSON}" | ${JQ_BIN} -r '.[] | select(.value.plainText != "") | "\(.key)=\(.value.plainText)"' >> "${VALUES_LOG_FILE}"
    #fi
    #echo "${JENKINS_PARAMS}" > "${VALUES_JSON_FILE}"
  fi

  if [ "${MODE}" == "post-is" ]; then
    createPipelineVarsArray
    for i in "${PIPELINE_VARS[@]}"; do
      if [ "${LOG_PASSWDS}" == "0" ] && [[ "${i}" =~ "PASSWORD" ]]; then
        continue
      fi
      v="IS_${i}"
      if [ "${!v}" != "" ]; then
        echo "${i}=${!v}" >> "${VALUES_LOG_FILE}"
      fi
    done
  fi
}

checkJenkinsConfig() {
  [[ "${SKIP_JENKINS}" == 1 ]] && return
  if isJenkinsInCluster ; then
    logMessage "Jenkins is running in cluster - skipping remaining checks..."
  else
    logMessage "Checking plugins..."
    checkJenkinsPlugins
    logMessage "Checking approved scripts..."
    checkJenkinsScriptApprovals
    logMessage "Checking nodes..."
    checkJenkinsNodes
    logMessage "Checking credentials..."
    validateJenkinsCredentials
    logMessage "Checking global pipeline libraries..."
    checkJenkinsGlobalLibs
    logMessage "Checking ssh configuration..."
    checkSSHSetup
  fi
}

getPipelineParameterDefault() {
  PARAM_VALUE=$(getPipelineDefaults ${1} | ${JQ_BIN} -r .${2})
  echo "${PARAM_VALUE}"
}

checkJenkinsNodes() {
  NODE_STATUS=$(${CURL_BIN} -sk "${JENKINS_URL}/manage/computer/api/json?depth=1")
  OFFLINE_NODES=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[]| select(.offline=='true').displayName')
  if [ ! -z "${OFFLINE_NODES}" ] ; then
    logError "193" "One or more Jenkins nodes found in an 'offline' state."
    printf '%s\n' "${OFFLINE_NODES}"
  fi

  NODE_LABELS=$(echo "${NODE_STATUS}" | ${JQ_BIN} -r '.computer[].assignedLabels[].name')
  UBER_VERSION=$(getPipelineParameterDefault HELIX_ONPREM_DEPLOYMENT PLATFORM_HELM_VERSION)
  if [ "${UBER_VERSION}" == "" ]; then
    logMessage "Could not read the PLATFORM_HELM_VERSION value from the HELIX_ONPREM_DEPLOYMENT pipeline - node label checks skipped."
  else
    if [ ${UBER_VERSION::5} -ge 20252 ]; then
      HELM_NODE_LABEL="ansible-master-latest"
    else
      HELM_NODE_LABEL="ansible-master"
    fi
    if ! echo "${NODE_LABELS}" | grep -Fxq "${HELM_NODE_LABEL}" ; then
      logError "194" "No Jenkins nodes found with the required label '${HELM_NODE_LABEL}'."
    fi
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
  JK_PLUGINS=$(${CURL_BIN} -sk "${JENKINS_URL}/pluginManager/api/json?depth=1" | ${JQ_BIN} -r '.plugins[].shortName')
  for i in "${EXPECTED_PLUGINS[@]}" ; do
    if ! echo "${JK_PLUGINS}" | grep -wq "${i}" ; then
      logError "195" "Jenkins plugin '${i}' is missing."
    fi
  done
  # Test for permissive script plugin
  if [[ "${JK_PLUGINS[*]}" =~ "permissive-script-security" ]]; then
    SKIP_JENKINS_SCRIPTAPPROVAL_CHECK=1
  fi
}

# NOT USED
checkJenkinsCredentials() {
  # Get list of credentials and check for expected IDs
  EXPECTED_CREDENTIALS="${JENKINS_CREDS[@]}"
  JK_CREDS=$(${CURL_BIN} -sk "${JENKINS_URL}/credentials/api/json?depth=3"  | ${JQ_BIN} -r '.stores.system.domains._.credentials[].id')
  for i in "${EXPECTED_CREDENTIALS[@]}" ; do
    if ! echo "${JK_CREDS}" | grep -wq "${i}" ; then
      logError "196" "Jenkins credentials with id '${i}' is missing."
    fi
  done
}

checkForNewHITT() {
  [[ "${SKIP_UPDATE_CHECK}" == "1" ]] && return
  if [ "$(${CURL_BIN} -o /dev/null --silent -Iw '%{http_code}' --connect-timeout 10 "${HITT_URL}")" != "200" ]; then
    return
  fi
  REMOTE_TMP=$(mktemp) || return
  if ! ${CURL_BIN} -sL "${HITT_URL}" --connect-timeout 10 -o "${REMOTE_TMP}"; then
    rm -f "${REMOTE_TMP}"
    return
  fi
  REMOTE_MD5=$(md5sum "${REMOTE_TMP}" | awk '{print $1}')
  remote_line=$(grep -m1 -E '^HITT_BUILD_VERSION=' "${REMOTE_TMP}" || true)
  rm -f "${REMOTE_TMP}"
  REMOTE_HITT_BUILD_VERSION=""
  if [[ -n "${remote_line}" ]]; then
    val=${remote_line#HITT_BUILD_VERSION=}
    val=${val#\"}
    val=${val%\"}
    val=${val#\'}
    val=${val%\'}
    if [[ "${val}" =~ ^[0-9]{8}-[0-9]{1,2}$ ]]; then
      REMOTE_HITT_BUILD_VERSION="${val}"
    fi
  fi
  LOCAL_MD5=$(md5sum $0 | awk '{print $1}')
  if [ "${REMOTE_MD5}" != "${LOCAL_MD5}" ]; then
    if [[ -n "${REMOTE_HITT_BUILD_VERSION}" ]]; then
      logStatus "${GREEN}An updated version of HITT is available (${REMOTE_HITT_BUILD_VERSION}) - please see https://bit.ly/gethitt or update by running:\n${YELLOW}curl -skO ${HITT_URL}${NORMAL}"
    else
      logStatus "${GREEN}An updated version of HITT is available - please see https://bit.ly/gethitt or update by running:\n${YELLOW}curl -skO ${HITT_URL}${NORMAL}"
    fi
    echo
    read -r -s -n1 -t3 -p"Press any key to continue or Ctrl+C to cancel..."
    echo
  fi
}

unpackSSLPoke() {
  echo "${SSLPOKE_PAYLOAD}" | tr -d ' ' | ${BASE64_BIN} -d > SSLPoke.class
}

checkHITTconf() {
  CONF_UPDATED=0
  while IFS="=" read -r param value; do
    if ! grep "^${param}" "${1}" >/dev/null 2>&1; then
      echo "${param}=${value}" >> "${1}"
      CONF_UPDATED=1
    fi
  done < <(grep '.=' .hitt.conf)
  [[ $CONF_UPDATED == 1 ]] && logStatus "${GREEN}HITT config file '${1}' has been updated with a new parameter.${NORMAL}"
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

  runJenkinsScript "${SCRIPT}"
}

validateJenkinsKubeconfig() {
  getKubeconfigFromJenkins > kubeconfig.jenkins
  if [ ! -s ./kubeconfig.jenkins ]; then
    logWarning "028" "Failed to extract kubeconfig file from Jenkins - skipping validation."
    return
  fi
#  KUBECONFIG_JSON=$(KUBECONFIG=./kubeconfig.jenkins ${KUBECTL_BIN} config view -o json 2>/dev/null)
#  KUBECONFIG_CONTEXTS=($(echo "${KUBECONFIG_JSON}" | ${JQ_BIN} -r '.contexts[].name'))
#  if [ "${#KUBECONFIG_CONTEXTS[@]}" -eq 0 ]; then
#    logError "197" "Unable to verify kubeconfig file from Jenkins KUBECONFIG credential."
#    return
#  fi
#  if [ "${#KUBECONFIG_CONTEXTS[@]}" != "1" ]; then
#    logMessage "Multiple contexts found in kubeconfig file - please select the cluster context you plan to use:"
#    while [ "${SELECTED_CONTEXT}" == "" ]; do
#        SELECTED_CONTEXT=$(selectFromArray KUBECONFIG_CONTEXTS)
#    done
#    KUBECONFIG=./kubeconfig.jenkins ${KUBECTL_BIN} use-context "${SELECTED_CONTEXT}" &> /dev/null
#  fi

  if ! timeout 5s ${KUBECTL_BIN} --kubeconfig=./kubeconfig.jenkins -n "${HP_NAMESPACE}" cluster-info > /dev/null 2>>${HITT_ERR_FILE}; then
    logError "197" "Unable to verify kubeconfig file from Jenkins KUBECONFIG credential."
    SKIP_CLEANUP=1
  else
    logMessage "Verified Jenkins KUBECONFIG credential contains a valid kubeconfig file." 1
  fi
}

getJenkinsGlobalLibs() {
  # Optional first argument: trusted (default) or untrusted — which Jenkins global library list to read.
  local scope="${1:-trusted}"
  local GLOBAL_LIBS_JAVA
  case "${scope}" in
    trusted)
      GLOBAL_LIBS_JAVA="GlobalLibraries"
      ;;
    untrusted)
      GLOBAL_LIBS_JAVA="GlobalUntrustedLibraries"
      ;;
    *)
      logError "999" "getJenkinsGlobalLibs: first argument must be 'trusted' or 'untrusted' (default: trusted)." 1
      ;;
  esac

  SCRIPT="import groovy.json.JsonOutput
    import org.jenkinsci.plugins.workflow.libs.${GLOBAL_LIBS_JAVA}
    import org.jenkinsci.plugins.workflow.libs.SCMSourceRetriever
    def globalLibraries = ${GLOBAL_LIBS_JAVA}.get()
    def libraryDetails = globalLibraries.libraries.collect { lib ->
        def retrieverType = lib.retriever?.class?.simpleName
        def remoteUrl = null
        if (lib.retriever instanceof SCMSourceRetriever) {
            def scmSource = lib.retriever.scm
            if (scmSource && scmSource.hasProperty(\"remote\")) {
                remoteUrl = scmSource.remote
            }
        }
        return [
            name          : lib.name,
            defaultVersion: lib.defaultVersion,
            retrieverType : retrieverType,
            implicit      : lib.implicit,
            remoteUrl     : remoteUrl
        ]
    }
    def jsonOutput = JsonOutput.toJson(libraryDetails)
    println(JsonOutput.prettyPrint(jsonOutput))"

  runJenkinsScript "${SCRIPT}"
}

expandLeadingTilde() {
  # Expand leading ~ or ~user in a path (replaces eval echo for Jenkins library remoteUrl paths).
  local path="$1"
  case "${path}" in
    "~")
      printf '%s\n' "${HOME}"
      ;;
    "~/"*)
      printf '%s/%s\n' "${HOME}" "${path:2}"
      ;;
    "~"*)
      local without="${path#\~}"
      local user="${without%%/*}"
      local suffix=""
      local homedir
      if [[ "${without}" == */* ]]; then
        suffix="${without#*/}"
      fi
      homedir=$(getent passwd "${user}" 2>/dev/null | cut -d: -f6)
      [ -z "${homedir}" ] && homedir="${HOME}"
      if [ -n "${suffix}" ]; then
        printf '%s/%s\n' "${homedir}" "${suffix}"
      else
        printf '%s\n' "${homedir}"
      fi
      ;;
    *)
      printf '%s\n' "${path}"
      ;;
  esac
}

checkJenkinsGlobalLibs() {
  JLIBS_JSON=$(getJenkinsGlobalLibs trusted)
  UNTRUSTED_JSON=$(getJenkinsGlobalLibs untrusted)
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
      LIB_URL=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '.[] | select(.name=="'${i}'").remoteUrl')
      LIB_PATH=$(echo "${LIB_URL#*://}")
      REPO_PATH=$(echo "${LIB_PATH#*/}")
      if [[ "${REPO_PATH}" =~ ^~ ]] ; then
        REPO_PATH=$(expandLeadingTilde "${REPO_PATH}")
      else
        REPO_PATH="/${REPO_PATH}"
      fi

      if [ "${LIB_VERSION}" != "master" ]; then
        logError "150" "The 'Default version' of the '${LIB_NAME}' library is not the expected value of 'master'."
      fi
      if [ "${LIB_TYPE}" != "SCMSourceRetriever" ]; then
        logError "179" "The 'Retrieval method' of the '${LIB_NAME}' library is not the expected value 'Modern SCM'."
      fi
      if [[ ! "${LIB_URL}" =~ ^ssh://.* ]] || ! echo "${LIB_PATH}" | grep -q "^${CRED_USER}@" ; then
        logError "233" "The 'Project Repository' value of the '${LIB_NAME}' global pipeline library is not set correctly, it should begin with 'ssh://<GIT_USER>@'."
      fi
      if [[ "${REPO_PATH}" =~ [[:space:]]+$ ]]; then
        logError "248" "The 'Project Repository' value of the '${LIB_NAME}' global pipeline library has a trailing space which must be removed."
        REPO_PATH=$(echo -n "${REPO_PATH}" | sed 's/[[:space:]]\+$//') # trim trailing spaces
      fi
      if [ ! -d "${REPO_PATH}" ]; then
        logError "234" "The '${REPO_PATH}' directory in the 'Project Repository' value of the '${LIB_NAME}' global pipeline library does not exist.  Verify the path to the directory."
      else
        if [ "${REPO_PATH##*/}" != "${i}.git" ]; then
          logError "246" "'${REPO_PATH##*/}' is not the expected git repository for this global library - expected '${i}.git'."
        fi
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
  LIB_DUP_TRUSTED=$(echo "${JLIBS_JSON}" | ${JQ_BIN} -r '[.[].name] | group_by(.) | map(select(length > 1) | .[0]) | join(" ")')
  if [ -n "${LIB_DUP_TRUSTED}" ]; then
    logError "260" "Duplicate Global Trusted Pipeline Library name(s) in Jenkins: '${LIB_DUP_TRUSTED}'. Each name must appear only once under Global Trusted Libraries."
  fi
  LIB_DUP_UNTRUSTED=$(echo "${UNTRUSTED_JSON}" | ${JQ_BIN} -r '[.[].name] | group_by(.) | map(select(length > 1) | .[0]) | join(" ")')
  if [ -n "${LIB_DUP_UNTRUSTED}" ]; then
    logError "261" "Duplicate Global Untrusted Pipeline Library name(s) in Jenkins: '${LIB_DUP_UNTRUSTED}'. Each name must appear only once under Global Untrusted Libraries."
  fi
  LIB_IN_BOTH=$(printf '%s\n%s\n' "${JLIBS_JSON}" "${UNTRUSTED_JSON}" | ${JQ_BIN} -s -r '.[0] as $t | .[1] as $u | ($t | map(.name)) as $tn | ($u | map(.name)) as $un | ($tn | unique | map(select(. as $n | ($un | index($n) != null))) | join(" "))')
  if [ -n "${LIB_IN_BOTH}" ]; then
    logError "259" "The following pipeline libraries are defined in both Global Trusted Libraries and Global Untrusted Libraries: '${LIB_IN_BOTH}'. Remove the duplicate so each library exists in only one list."
  fi
  if [ "${MISSING_LIBS}" != "" ]; then
    UNTRUSTED_FOUND=""
    for i in "${JENKINS_LIBS[@]}" ; do
      if ! echo "${JLIBS_JSON}" | ${JQ_BIN} -e --arg n "${i}" '.[] | select(.name==$n)' >/dev/null 2>&1; then
        if echo "${UNTRUSTED_JSON}" | ${JQ_BIN} -e --arg n "${i}" '.[] | select(.name==$n)' >/dev/null 2>&1; then
          UNTRUSTED_FOUND+=" '${i}'"
        fi
      fi
    done
    ERR_MSG="One or more Jenkins global pipeline libraries not found under Global Trusted Libraries -'${MISSING_LIBS}'"
    if [ "${UNTRUSTED_FOUND}" != "" ]; then
      ERR_MSG+=" These libraries are configured under Global Untrusted Libraries instead:'${UNTRUSTED_FOUND}'; move them to Global Trusted Libraries."
    fi
    logError "215" "${ERR_MSG}" 1
  else
    logMessage "Expected global pipeline libraries found in Jenkins." 1
  fi
}

getPipelineValuesJSON() {
  SCRIPT="import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import hudson.model.ParametersAction
    def jobName = 'HELIX_ONPREM_DEPLOYMENT'
    def job = Jenkins.instance.getItemByFullName(jobName)
    def lastBuild = job.${1}(${2})
    def paramsAction = lastBuild.getAction(ParametersAction)
    def paramMap = [:]
    paramsAction.getParameters().each { param ->
        paramMap[param.getName()] = param.getValue().toString()
    }
    def json = JsonOutput.prettyPrint(JsonOutput.toJson(paramMap))
    println json"
  runJenkinsScript "${SCRIPT}"
}


getPipelineDefaults() {
  SCRIPT="import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import hudson.model.*
    import hudson.plugins.validating_string_parameter.ValidatingStringParameterDefinition
    def jobName = '${1}'
    def job = Jenkins.instance.getItemByFullName(jobName)
    def prop = job.getProperty(ParametersDefinitionProperty)
    def result = [:]
    if (prop) {
        prop.parameterDefinitions.each { param ->
            def value = null
            switch (param) {
                case ChoiceParameterDefinition:
                    value = param.choices ? param.choices[0] : ''
                    break
                case PasswordParameterDefinition:
                    // Extracts plain text from the default secret
                    value = param.defaultValueAsSecret?.getPlainText() ?: ''
                    break
                case BooleanParameterDefinition:
                    // Boolean must be handled carefully as 'false' is a valid value
                    value = param.defaultValue
                    break
                case StringParameterDefinition:
                case TextParameterDefinition:
                case ValidatingStringParameterDefinition:
                    value = param.defaultValue ?: ''
                    break
                default:
                    if (param.metaClass.hasProperty(param, 'defaultValue') && param.defaultValue != null) {
                        value = param.defaultValue.toString()
                    } else if (param.metaClass.respondsTo(param, 'getDefaultParameterValue')) {
                        value = param.getDefaultParameterValue()?.value?.toString() ?: ''
                    }
                    break
            }
            result[param.name] = value
        }
    }
    println JsonOutput.prettyPrint(JsonOutput.toJson(result))"
    runJenkinsScript "${SCRIPT}"
  }

getPipelineSectionParams() {
  # $1 = Jenkins job name. Returns JSON array of parameter names in the PIPELINES UI section.
  local job_name="${1:-HELIX_ONPREM_DEPLOYMENT}"
  SCRIPT="import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import hudson.model.ParametersDefinitionProperty
    def jobName = '${job_name}'
    def job = Jenkins.instance.getItemByFullName(jobName)
    def prop = job.getProperty(ParametersDefinitionProperty)
    def params = []
    def inPipelinesSection = false
    def sectionDone = false
    if (prop) {
        prop.parameterDefinitions.each { param ->
            if (sectionDone) {
                return
            }
            def className = param.getClass().simpleName
            if (className.contains('ParameterSeparator')) {
                if (inPipelinesSection) {
                    sectionDone = true
                    return
                }
                def sectionHeader = param.metaClass.hasProperty(param, 'sectionHeader') ? param.sectionHeader : null
                if (param.name == 'SEPARATOR_PIPELINES' || sectionHeader == 'PIPELINES') {
                    inPipelinesSection = true
                }
            } else if (inPipelinesSection) {
                params.add(param.name)
            }
        }
    }
    println JsonOutput.toJson(params)"
  runJenkinsScript "${SCRIPT}"
}

getPipelineFileParams() {
  # $1 = Jenkins job name. Returns JSON array of FileParameterDefinition names.
  local job_name="${1:-HELIX_ONPREM_DEPLOYMENT}"
  SCRIPT="import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import hudson.model.FileParameterDefinition
    import hudson.model.ParametersDefinitionProperty
    def jobName = '${job_name}'
    def job = Jenkins.instance.getItemByFullName(jobName)
    def prop = job.getProperty(ParametersDefinitionProperty)
    def params = []
    if (prop) {
        prop.parameterDefinitions.each { param ->
            if (param instanceof FileParameterDefinition) {
                params.add(param.name)
            }
        }
    }
    println JsonOutput.toJson(params)"
  runJenkinsScript "${SCRIPT}"
}

# Old version
xgetPipelineDefaults() {
  SCRIPT="import groovy.json.JsonOutput
    import jenkins.model.Jenkins
    import hudson.model.ParametersDefinitionProperty
    def jobName = '${1}'
    def job = Jenkins.instance.getItemByFullName(jobName)
    def parameterDefs = job.getProperty(ParametersDefinitionProperty)?.parameterDefinitions
    def result = [:]
    parameterDefs.each { param ->
        def value = null
        if (param.class.simpleName == 'ChoiceParameterDefinition') {
            def choices = param.choices
            if (choices && choices[0].toString().trim()) {
                value = choices[0].toString().trim()
            }
        } else if (param.metaClass.hasProperty(param, 'defaultValue')) {
            def defVal = param.defaultValue
            if (defVal != null && defVal.toString().trim()) {
                value = defVal.toString().trim()
            }
        }
        if (value) {
            result[param.name] = value
        }
    }
    println JsonOutput.prettyPrint(JsonOutput.toJson(result))"
  runJenkinsScript "${SCRIPT}"
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
  runJenkinsScript "${SCRIPT}"
}

checkSSHknown_hosts() {
  if ! which ssh-keygen >/dev/null 2>&1; then
    logWarning "039" "'ssh-keygen' command not found - skipping passwordless ssh checks."
    return
  fi
  for h in "${SHORT_HOSTNAME}" "${LONG_HOSTNAME}"; do
    if ! ssh-keygen -F "${h}" >/dev/null 2>&1 ; then
      logError "237" "Hostname '${h}' is not set up for passwordless ssh - please run 'ssh ${USER}@${h}' to configure this."
    fi
  done
}

validateJenkinsCredentials() {
  JCREDS_JSON=$(getJenkinsCredentials)
  PWD_ARRAY=()
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
        PWD_ARRAY+=("${CRED_PWD}")
        if [ "${CRED_PWD}" == "" ]; then
          logError "183" "The password for the '${ID}' credential is blank but should be set to the password of the user '${CRED_USER}'."
        else
          [[ -n "${DUMP_JCREDS}" ]] && logMessage "ID=${ID} / Username=${BOLD}${GREEN}${CRED_USER}${NORMAL} / Password=${BOLD}${RED}${CRED_PWD}${NORMAL}"
        fi
      fi
    fi
  done

  if [ "${DUMP_JCREDS}" == "1" ]; then return; fi

  INIT_PWD="${PWD_ARRAY[0]}"
  BAD_CRED_PWD=0
  for p in "${PWD_ARRAY[@]}"; do
    if [ "${p}" != "${INIT_PWD}" ]; then
      BAD_CRED_PWD=1
    fi
  done
  if [ "${BAD_CRED_PWD}" == "1" ]; then
    logError "230" "The passwords for the Jenkins credentials are not all set to the same value.  Run 'bash $0 -j' to display the values."
  else
    if ! which sshpass  > /dev/null 2>&1 ; then
      logWarning "038" "'sshpass' command not found - please install it to enable Jenkins credentials password validation."
    else
      if ssh -v -o BatchMode=yes "${CRED_USER}@${LONG_HOSTNAME}" whoami 2>&1 | grep -i continue | grep -qi password ; then
        if ! sshpass -p "${CRED_PWD}" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new "${CRED_USER}@${LONG_HOSTNAME}" whoami >/dev/null 2>&1 ; then
          logError "231" "The password set for the git user in the Jenkins credentials is not correct. Run 'bash $0 -j' to display the values."
        fi
      else
        logWarning "045" "ssh PasswordAuthentication appears to be disabled - skipping Jenkins credentials password validation..."
      fi
    fi
  fi

  if [ "${MISSING_CREDS}" != "" ]; then
    logError "198" "One or more Jenkins credentials not found -${MISSING_CREDS}"
  else
    logMessage "Expected credentials found in Jenkins." 1
  fi

  if echo "${MISSING_CREDS}" | grep -vq kubeconfig ; then
    validateJenkinsKubeconfig
  fi
}

getJenkinsApprovedScripts() {
  SCRIPT='import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval
    import groovy.json.JsonOutput
    ScriptApproval scriptApproval = ScriptApproval.get()
    List<String> approvedSignatures = scriptApproval.getApprovedSignatures()
    String jsonOutput = JsonOutput.prettyPrint(JsonOutput.toJson([approvedSignatures: approvedSignatures]))
    println jsonOutput'
    runJenkinsScript "${SCRIPT}"
}

checkJenkinsScriptApprovals() {
  if [[ -n "${SKIP_JENKINS_SCRIPTAPPROVAL_CHECK+x}" ]]; then
    logMessage "Jenkins 'permissive-script-security' plugin found - skipping script approval checks..." 1
    return
  fi
  APPROVED_SCRIPTS=$(getJenkinsApprovedScripts)
  for i in "getRawBuild" "getLog" ; do
    if ! echo "${APPROVED_SCRIPTS}" | ${JQ_BIN} '.approvedSignatures' | grep -q "${i}" ; then
      logError "238" "Missing script approval in Jenkins - '${i}' not found in the list of approved scripts.  See https://community.bmc.com/s/article/Helix-ITSM-Onprem-How-to-add-Jenkins-in-process-script-approvals"
    fi
  done
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
      logMessage "Helix IS platform-admin-ext service is of type ClusterIP." 1
    fi
    ;;
  NodePort)
    logMessage "Helix IS platform-admin-ext service is of type NodePort." 1
    ;;
  *)
    logWarning "026" "Helix IS platform-admin-ext service is of type '${PLATFORM_EXT_SVC_TYPE}' and not the expected ClusterIP or NodePort."
    ;;
esac
}

logPods() {
  # ns name
  logMessage "Getting pods from '${1}'..." 1
  ${KUBECTL_BIN} -n ${1} get pods -o wide 2>/dev/null > k8s-get-pods-${1}.log
}

logEvents() {
  # ns name
  logMessage "Getting events from '${1}'..." 1
  ${KUBECTL_BIN} -n ${1} events 2>/dev/null > k8s-events-${1}.log
}

getMessageJSON() {
  # $1 = message id (e.g. 127, 001)
  MSG_JSON=$(${JQ_BIN} -c --arg id "${1}" '
    [.[] | select(.id == $id)][0] // empty
  ' <<< "${ALL_MSGS_JSON}")
  if [ -z "${MSG_JSON}" ]; then
    MSG_JSON=$(${JQ_BIN} -cn --arg id "${1}" '{
      id: $id,
      cause: "Message details not found for id \($id).",
      impact: "Message details cannot be displayed.",
      remediation: "Please report to mark.walters@helixops.ai"
    }')
  fi
}

loadMessageFields() {
  HITT_MSG_CAUSE=$(${JQ_BIN} -r '.cause // empty' <<< "${MSG_JSON}")
  HITT_MSG_IMPACT=$(${JQ_BIN} -r '.impact // empty' <<< "${MSG_JSON}")
  HITT_MSG_REMEDIATION=$(${JQ_BIN} -r '.remediation // empty' <<< "${MSG_JSON}")
}

printMessageDetails() {
  printf "\n"
  [[ -n "${MSG}" ]] && printf "${BOLD}Message:${NORMAL} ${MSG}\n"
  printf "${BOLD}${YELLOW}Cause:${NORMAL} %s\n" "${HITT_MSG_CAUSE}"
  printf "${BOLD}${RED}Impact:${NORMAL} %s\n" "${HITT_MSG_IMPACT}"
  printf "${BOLD}${GREEN}Remediation:${NORMAL} %s\n" "${HITT_MSG_REMEDIATION}"
}

showMessageById() {
  getMessageJSON "${1}"
  loadMessageFields
  MSG="(${1}) ${HITT_MSG_CAUSE}"
  printMessageDetails
}

isHittActionRun() {
  [[ -n "${MODE}" || -n "${FIXOPTS}" || -n "${UTILOPTS}" || -n "${PIPELINEOPTS}" \
     || -n "${TCTL_CMD}" || -n "${BUNDLE_ID}" || -n "${PIPELINE_NAME}" || -n "${DUMP_JCREDS}" ]]
}

logMessageDetails() {
  # MSG_ID
  [[ "${1}" == "999" ]] && return # Don't log 999 messages
  # Suppress MSG_JSON parsing to reduce clutter
  # 1. Capture the original state
  if [[ $- =~ x ]]; then
      xtrace_was_on=true
  else
      xtrace_was_on=false
  fi
  # 2. Turn off tracing safely
  set +x
  getMessageJSON "${1}"
  loadMessageFields
  # Re-enable debugging if set
  if [ "$xtrace_was_on" = true ]; then
      set -x
  fi
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
  if isJenkinsInCluster ; then
    return
  fi
  logMessage "Checking OS binaries..."
  MISSING_BINS=()
  for i in ansible dos2unix python xmlstarlet yq; do
    if ! which "${i}" > /dev/null 2>&1; then
      MISSING_BINS+=("${i}")
    fi
  done
  if [ -n "${MISSING_BINS[*]}" ]; then
    logError "239" "One or more of the required OS tools were not found. Please ensure these commands are available - '${MISSING_BINS[*]}'. Note: 'yq' is only required for ITSM 25.3.01 and later."
  fi

  if [ "${MODE}" == "jenkins" ]; then
    return
  fi

  if [ -z "${IS_VERSION}" ]; then
    logMessage "IS version has not been detected - skipping checks."
    return
  fi

  IS_MAJOR_VERSION="${IS_VERSION:2:3}"

  # if IS <=22.x then kubectl must be <= 1.27
  if [ "${IS_MAJOR_VERSION}" -lt 233 ]; then
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
    if [ "${IS_MAJOR_VERSION}" -ge 221 ] && [ "${IS_MAJOR_VERSION}" -lt 233 ]; then
      MAX_ANSIBLE_VERSION="2.9"
    fi
    if [ "${IS_MAJOR_VERSION}" -ge 233 ] && [ "${IS_MAJOR_VERSION}" -lt 252 ]; then
      MAX_ANSIBLE_VERSION="2.15"
    fi
    if [ "${IS_MAJOR_VERSION}" -ge 252 ]; then
      MAX_ANSIBLE_VERSION="2.18"
    fi

    ANSIBLE_VERS=$(ansible-playbook /dev/stdin << 'EOF' 2>/dev/null | grep 'msg:' | xargs
---
- hosts: localhost
  gather_facts: true
  tasks:
    - debug:
        msg: "{{ ansible_version.full }}={{ ansible_python_version }}={{ ansible_python.executable }}"
EOF
    )
    ANSIBLE_VERS_CLEAN="${ANSIBLE_VERS#msg: }"
    IFS='=' read -r ANSIBLE_VERSION ANSIBLE_PYTHON_VERSION ANSIBLE_PYTHON_EXECUTABLE <<< "${ANSIBLE_VERS_CLEAN}"
#    ANSIBLE_VERSION=$(ansible --version 2>/dev/null | head -1 | grep -oP '\d+.\d+')
#    ANSIBLE_VERSION=$(ANSIBLE_STDOUT_CALLBACK=json ansible localhost -m ansible.builtin.debug -a "msg={{ ansible_version.full }}" 2>/dev/null | jq -r '.plays[0].tasks[0].hosts.localhost.msg' | grep -oP '\d+.\d+')
    if [ -z "${ANSIBLE_VERSION}" ]; then
      logError "216" "Unable to determine the version of ansible."
    else
      ANSIBLE_VERSION=$(echo "${ANSIBLE_VERSION}" | grep -oP '\d+.\d+')
      if [ $(versionFmt "${ANSIBLE_VERSION}") -gt $(versionFmt "${MAX_ANSIBLE_VERSION}") ]; then
        logError "208" "The installed version of ansible '${ANSIBLE_VERSION}' is not supported - required version must be no greater than '${MAX_ANSIBLE_VERSION}'."
      else
        logMessage "Using ansible version '${ANSIBLE_VERSION}'."
        if ! isJmespathInstalled ; then
#          ANSIBLE_FACTS_JSON=$(ANSIBLE_STDOUT_CALLBACK=json ansible -m setup localhost 2>>${HITT_ERR_FILE})
#          ANSIBLE_PYTHON_VERSION=$(echo "${ANSIBLE_FACTS_JSON}" | ${JQ_BIN} -r '.plays[0].tasks[0].hosts.localhost.ansible_facts.ansible_python_version')
#          ANSIBLE_PYTHON_EXECUTABLE=$(echo "${ANSIBLE_FACTS_JSON}" | ${JQ_BIN} -r '.plays[0].tasks[0].hosts.localhost.ansible_facts.ansible_python.executable')
#          ANSIBLE_PYTHON_VERSION=$(ANSIBLE_STDOUT_CALLBACK=json ansible -m setup localhost 2>/dev/null | sed '/^{/,/^}/p' | ${JQ_BIN} -r .plays[0].tasks[0].hosts.localhost.ansible_facts.ansible_python.executable)
          logError "209" "Unable to verify that 'jmespath' is installed for python version '${ANSIBLE_PYTHON_VERSION}' used by ansible - '${ANSIBLE_PYTHON_EXECUTABLE}'."
        fi
      fi
    fi

    ANSIBLE_CFG_FILE=/etc/ansible/ansible.cfg
    ANSIBLE_CFG_MISSING=""
    if [ ! -f "${ANSIBLE_CFG_FILE}" ]; then
      logError "210" "Ansible configuration file '${ANSIBLE_CFG_FILE}' not found - skipping checks."
    else
      logMessage "Checking ansible configuration file '${ANSIBLE_CFG_FILE}'." 1
      ANSIBLE_CFG_VALS=(bin_ansible_callbacks=true stdout_callback=yaml host_key_checking=false ssh_args=-ocontrolmaster=auto retries=3 pipelining=true)
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

  if ! which ansible-galaxy > /dev/null 2>&1 ; then
    logWarning "036" "'ansible-galaxy' command not found - skipping collection checks."
  else
    if ! ansible-galaxy collection list 2>/dev/null | grep -q community.general ; then
      logError "225" "The community.general module for ansible is missing - please install it with the command 'ansible-galaxy collection install community.general'."
    fi
  fi
}

getJenkinsCrumb() {
  JENKINS_CRUMB=$(${CURL_BIN} -c .cookies -sk "${JENKINS_URL}/crumbIssuer/api/json" | ${JQ_BIN} -r .crumb )
}

runJenkinsScript() {
  #1 groovy script
  ${CURL_BIN} --max-time 10 -b .cookies --data-urlencode "script=${1}" -skv -H "Jenkins-Crumb:${JENKINS_CRUMB}" "${JENKINS_URL}/scriptText" 2>>${HITT_ERR_FILE}
}

isOpenShift() {
  OPENSHIFT_VERSION=""
  if ${KUBECTL_BIN} get clusteroperators >/dev/null 2>&1; then
    OPENSHIFT=1
    OPENSHIFT_VERSION=$(${KUBECTL_BIN} get clusterversion -o jsonpath='{.items[].spec.desiredUpdate.version}')
  fi
}

tidyUp() {
  cleanUp stop
  reportResults
  # DEBUG only
  dumpVARs
  if [ "${MODE}" != "post-hp" ]; then
    saveAllPipelineConsoleOutput
  fi
  [ -f "${HITT_LOG_FILE}" ] && cat "${HITT_LOG_FILE}" | sed -e 's/\x1b\[[0-9;]*m//g' > hitt.txt
  [ -f "${HITT_MSG_FILE}" ] && cat "${HITT_MSG_FILE}" | sed -e 's/\x1b\[[0-9;]*m//g' > hittmsgs.txt
  ${ZIP_BIN} -q - *.log hitt*.txt k8s*.txt *.json > hittlogs.zip
}

getPodNameByLabel() {
  # namespace label-filter
  ${KUBECTL_BIN} -n "${1}" get pod -l "${2}" -o custom-columns=:metadata.name --no-headers | head -1
}

downloadISCacertsFromSecret() {
  local IS_CACERTS_JSON IS_CACERTS
  CACERTS_FILENAME="${CACERTS_FILENAME:-is-sealcacerts}"
  logMessage "Downloading cacerts from the '${IS_NAMESPACE}' cacerts secret..."
  if ! ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts >/dev/null 2>&1; then
    logError "999" "'cacerts' secret not found in Helix IS namespace '${IS_NAMESPACE}'." 1
  fi
  IS_CACERTS_JSON=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts -o json 2>>"${HITT_ERR_FILE}")
  IS_CACERTS=$(echo "${IS_CACERTS_JSON}" | ${JQ_BIN} -r '.data.cacerts')
  if [ "${IS_CACERTS}" == "null" ] || [ -z "${IS_CACERTS}" ]; then
    logError "999" "Required file 'cacerts' not found in the cacerts secret. Keys present:"
    echo "${IS_CACERTS_JSON}" | ${JQ_BIN} -r '.data | keys[]?' 1>&2
    return 1
  fi
  echo "${IS_CACERTS}" | ${BASE64_BIN} -d > "${CACERTS_FILENAME}"
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi
  if ! ${KEYTOOL_BIN} -list -keystore "${CACERTS_FILENAME}" -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" >/dev/null 2>&1; then
    logError "999" "Downloaded cacerts file could not be opened — check CACERTS_SSL_TRUSTSTORE_PASSWORD for the IS namespace." 1
  fi
  logMessage "Downloaded cacerts from '${IS_NAMESPACE}' to '${CACERTS_FILENAME}'."
}

splitPemCertificatesToDir() {
  local pem_file=$1 out_dir=$2 count
  mkdir -p "${out_dir}"
  rm -f "${out_dir}"/cert_*.pem
  awk -v dir="${out_dir}" '
    BEGIN { n=0; fn="" }
    /-----BEGIN CERTIFICATE-----/ {
      n++
      fn=sprintf("%s/cert_%03d.pem", dir, n)
    }
    fn { print > fn }
  ' "${pem_file}"
  count=$(find "${out_dir}" -maxdepth 1 -name 'cert_*.pem' 2>/dev/null | wc -l | tr -d '[:space:]')
  echo "${count:-0}"
}

validatePemCertificateFile() {
  local pem_file=$1 out_dir=$2 cert_count cert_file idx subject end_date expiry_warn=$((28 * 24 * 3600))
  cert_count=$(grep -c "BEGIN CERTIFICATE" "${pem_file}" 2>/dev/null || true)
  cert_count=${cert_count:-0}
  if ! [[ "${cert_count}" =~ ^[0-9]+$ ]] || [ "${cert_count}" -eq 0 ]; then
    logError "999" "No certificates found in '${pem_file}' — expected a PEM file with one or more CERTIFICATE blocks." 1
  fi
  logMessage "Found ${cert_count} certificate(s) in '${pem_file}'."
  cert_count=$(splitPemCertificatesToDir "${pem_file}" "${out_dir}")
  cert_count=${cert_count:-0}
  if ! [[ "${cert_count}" =~ ^[0-9]+$ ]] || [ "${cert_count}" -eq 0 ]; then
    logError "999" "Unable to read certificates from '${pem_file}'." 1
  fi
  idx=0
  for cert_file in "${out_dir}"/cert_*.pem; do
    [[ -f "${cert_file}" ]] || continue
    idx=$((idx + 1))
    if ! ${OPENSSL_BIN} x509 -in "${cert_file}" -noout 2>>"${HITT_ERR_FILE}"; then
      logError "999" "Certificate ${idx} in '${pem_file}' is not a valid X.509 certificate." 1
    fi
    subject=$(${OPENSSL_BIN} x509 -in "${cert_file}" -noout -subject 2>/dev/null | sed 's/^subject=//')
    end_date=$(${OPENSSL_BIN} x509 -in "${cert_file}" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    logMessage "Certificate ${idx}: ${subject}"
    if ! ${OPENSSL_BIN} x509 -in "${cert_file}" -noout -checkend 0 >/dev/null 2>/dev/null; then
      logError "999" "Certificate ${idx} has expired (${end_date})." 1
    fi
    if ! ${OPENSSL_BIN} x509 -in "${cert_file}" -noout -checkend "${expiry_warn}" >/dev/null 2>/dev/null; then
      logWarning "999" "Certificate ${idx} expires within 4 weeks (${end_date}) — continuing."
    fi
  done
}

addcertNormalizeSha256Fingerprint() {
  echo "$1" | sed 's/://g' | tr '[:upper:]' '[:lower:]'
}

addcertPemSha256Fingerprint() {
  addcertNormalizeSha256Fingerprint "$(${OPENSSL_BIN} x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')"
}

addcertBuildKeystoreFingerprintSet() {
  ADD_CERT_KEYSTORE_FPS=$(mktemp addcert-fps.XXXXXX)
  ${KEYTOOL_BIN} -list -v -keystore "${CACERTS_FILENAME}" \
    -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" 2>>"${HITT_ERR_FILE}" \
    | awk '/SHA256:/ {
        fp=$0
        sub(/.*SHA256: /, "", fp)
        gsub(/:/, "", fp)
        print tolower(fp)
      }' > "${ADD_CERT_KEYSTORE_FPS}"
}

addcertKeystoreContainsFingerprint() {
  grep -qFx "${1}" "${ADD_CERT_KEYSTORE_FPS}" 2>/dev/null
}

addcertRecordKeystoreFingerprint() {
  echo "${1}" >> "${ADD_CERT_KEYSTORE_FPS}"
}

addcertCleanupKeystoreFingerprintSet() {
  [ -n "${ADD_CERT_KEYSTORE_FPS}" ] && rm -f "${ADD_CERT_KEYSTORE_FPS}"
  ADD_CERT_KEYSTORE_FPS=""
}

importPemCertificatesFromDir() {
  local cert_dir=$1 cert_file alias fp subject imported=0 skipped=0
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi
  addcertBuildKeystoreFingerprintSet
  for cert_file in "${cert_dir}"/cert_*.pem; do
    [[ -f "${cert_file}" ]] || continue
    fp=$(addcertPemSha256Fingerprint "${cert_file}")
    if addcertKeystoreContainsFingerprint "${fp}"; then
      subject=$(${OPENSSL_BIN} x509 -in "${cert_file}" -noout -subject 2>/dev/null | sed 's/^subject=//')
      logMessage "Certificate already present in cacerts (${subject}) — skipping."
      skipped=$((skipped + 1))
      continue
    fi
    alias="addcert-${fp:0:16}"
    if ${KEYTOOL_BIN} -import -trustcacerts -alias "${alias}" -file "${cert_file}" \
      -keystore "${CACERTS_FILENAME}" -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" -noprompt >/dev/null 2>>"${HITT_ERR_FILE}"; then
      logMessage "Added certificate to cacerts (alias '${alias}')."
      addcertRecordKeystoreFingerprint "${fp}"
      imported=$((imported + 1))
    else
      logError "999" "Failed to import certificate into cacerts (alias '${alias}')." 1
    fi
  done
  addcertCleanupKeystoreFingerprintSet
  ADD_CERT_IMPORTED_COUNT=${imported}
  logMessage "Imported ${imported} certificate(s) into '${CACERTS_FILENAME}' (${skipped} already present)."
}

ADD_CERT_CERT_DIR=""
ADD_CERT_IMPORTED_COUNT=0

addcertPreparePemCertDir() {
  local pem_file=$1
  checkBinary openssl
  addcertCleanupPemCertDir
  ADD_CERT_CERT_DIR=$(mktemp -d addcert-certs.XXXXXX)
  validatePemCertificateFile "${pem_file}" "${ADD_CERT_CERT_DIR}"
}

addcertCleanupPemCertDir() {
  [ -n "${ADD_CERT_CERT_DIR}" ] && rm -rf "${ADD_CERT_CERT_DIR}"
  ADD_CERT_CERT_DIR=""
}

addcertPreparePlatformContext() {
  checkToolVersion kubectl
  checkBinary keytool
  checkBinary openssl
  getVersions
  setVarsFromPlatform
  getDomain
  buildISAliasesArray
  CACERTS_FILENAME="is-sealcacerts"
}

addcertImportPemIntoKeystore() {
  local pem_file=$1
  if [ -z "${ADD_CERT_CERT_DIR}" ] || [ ! -d "${ADD_CERT_CERT_DIR}" ]; then
    addcertPreparePemCertDir "${pem_file}"
  fi
  importPemCertificatesFromDir "${ADD_CERT_CERT_DIR}"
}

addcertLoadJenkinsPipelineParams() {
  checkJenkinsIsRunning 1
  JENKINS_PARAMS=$(getPipelineValuesJSON getLastBuild)
}

gitGiteaCmd() {
  # Gitea in-cluster often uses a self-signed certificate.
  if isJenkinsInCluster; then
    ${GIT_BIN} -c http.sslVerify=false "$@"
  else
    ${GIT_BIN} "$@"
  fi
}

gitItsmRepoCmd() {
  gitGiteaCmd -C itsmrepo "$@"
}

setupGiteaUrlFromCluster() {
  GITEA_CREDS_JSON=$(getGITEACredentials)
  GITEA_ADMIN_USER=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_USER')
  GITEA_ADMIN_PASS=$(echo "${GITEA_CREDS_JSON}" | ${JQ_BIN} -r '.GITEA_ADMIN_PASS')
  GITEA_EP_JSON=$(getEPjson gitea "${CDE_NAMESPACE}")
  GITEA_HOST=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].host')
  GITEA_PROTOCOL=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].protocol')
  GITEA_PORT=$(echo "${GITEA_EP_JSON}" | ${JQ_BIN} -r '.[0].port')
  GITEA_URL="${GITEA_PROTOCOL}://${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}@${GITEA_HOST}:${GITEA_PORT}"
}

getItsmInstallerRepoUrl() {
  if isJenkinsInCluster; then
    setupGiteaUrlFromCluster
    if [ -z "${GITEA_HOST}" ] || [ "${GITEA_HOST}" == "null" ]; then
      logError "999" "Unable to find Gitea connection details — cannot access the ITSM installer repository." 1
    fi
    echo "${GITEA_URL}/${GITEA_ADMIN_USER}/itsm-on-premise-installer"
  else
    GIT_REPO_DIR=$(parseJenkinsParam GIT_REPO_DIR)
    if [ -z "${GIT_REPO_DIR}" ] || [ "${GIT_REPO_DIR}" == "null" ]; then
      logError "999" "GIT_REPO_DIR is not set in the HELIX_ONPREM_DEPLOYMENT pipeline — cannot access the ITSM installer repository." 1
    fi
    echo "${GIT_REPO_DIR}/ITSM_REPO/itsm-on-premise-installer.git"
  fi
}

cloneItsmInstallerCacertsSparse() {
  # $1 = repository URL
  local repo_url=$1 cacerts_path="pipeline/tasks/cacerts" default_branch
  export GIT_SSH_COMMAND="ssh -oBatchMode=yes"
  rm -rf itsmrepo
  default_branch=$(gitGiteaCmd ls-remote --symref "${repo_url}" HEAD 2>>"${HITT_ERR_FILE}" \
    | awk '/^ref:/ { sub("refs/heads/", "", $2); print $2; exit }')
  [ -z "${default_branch}" ] && default_branch=master
  logMessage "Checking out ${cacerts_path} from the ITSM installer repository (branch ${default_branch})..."
  if ! gitGiteaCmd clone --depth 1 --filter=blob:none --no-checkout \
    "${repo_url}" itsmrepo >>"${HITT_ERR_FILE}" 2>&1; then
    logError "999" "Failed to clone the ITSM installer repository." 1
  fi
  # Target is a single file — non-cone sparse checkout (cone mode needs --skip-checks for files).
  if ! gitItsmRepoCmd sparse-checkout init --no-cone >>"${HITT_ERR_FILE}" 2>&1 \
    || ! gitItsmRepoCmd sparse-checkout set "${cacerts_path}" >>"${HITT_ERR_FILE}" 2>&1; then
    if ! gitItsmRepoCmd sparse-checkout set --skip-checks "${cacerts_path}" >>"${HITT_ERR_FILE}" 2>&1; then
      logError "999" "Failed to configure sparse checkout for ${cacerts_path}." 1
    fi
  fi
  if ! gitItsmRepoCmd checkout "${default_branch}" >>"${HITT_ERR_FILE}" 2>&1; then
    logError "999" "Failed to check out ${cacerts_path} from branch '${default_branch}'." 1
  fi
  if [ ! -f "itsmrepo/${cacerts_path}" ]; then
    logError "999" "File ${cacerts_path} was not found in the ITSM installer repository." 1
  fi
  logMessage "Checked out ${cacerts_path} to itsmrepo/${cacerts_path}."
}

commitPushItsmInstallerCacerts() {
  # $1 = PEM file path (for commit message)
  local pem_file=$1 pem_name push_branch
  pem_name=$(basename "${pem_file}")
  cp -f "${CACERTS_FILENAME}" itsmrepo/pipeline/tasks/cacerts
  gitItsmRepoCmd add pipeline/tasks/cacerts
  if gitItsmRepoCmd diff --cached --quiet; then
    logMessage "No changes to pipeline/tasks/cacerts — nothing to commit."
    return 0
  fi
  if ! gitItsmRepoCmd -c user.name=HITT -c user.email=hitt@noreply.local \
    commit -m "HITT addcert: import certificate(s) from ${pem_name}" >>"${HITT_ERR_FILE}" 2>&1; then
    logError "999" "Failed to commit pipeline/tasks/cacerts to the ITSM installer repository." 1
  fi
  push_branch=$(gitItsmRepoCmd rev-parse --abbrev-ref HEAD 2>/dev/null)
  if [ -z "${push_branch}" ] || [ "${push_branch}" == "HEAD" ]; then
    push_branch=$(gitItsmRepoCmd remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}')
  fi
  [ -z "${push_branch}" ] && push_branch=master
  if ! gitItsmRepoCmd push origin "HEAD:${push_branch}" >>"${HITT_ERR_FILE}" 2>&1; then
    logError "999" "Failed to push pipeline/tasks/cacerts to the ITSM installer repository." 1
  fi
  logMessage "Committed and pushed pipeline/tasks/cacerts to the ITSM installer repository (branch ${push_branch})."
}

fixAddCertToSecret() {
  local pem_file=$1
  downloadISCacertsFromSecret
  addcertImportPemIntoKeystore "${pem_file}"
  if [ "${ADD_CERT_IMPORTED_COUNT}" -eq 0 ]; then
    logMessage "All certificate(s) from '${pem_file}' are already in cacerts — the cacerts secret was not changed."
    return 0
  fi
  validateCacertsFile IS
  if [ "${VALID_CACERTS}" != "0" ]; then
    logError "999" "Updated cacerts file did not pass validation — the cacerts secret was not changed." 1
  fi
  if askYesNo "Updated cacerts file is valid — replace the cacerts secret in '${IS_NAMESPACE}'?"; then
    replaceISCacertsSecret
    logMessage "cacerts secret in '${IS_NAMESPACE}' updated with certificate(s) from '${pem_file}'."
  else
    logMessage "No changes made to the cacerts secret in '${IS_NAMESPACE}'."
  fi
}

fixAddCertToGit() {
  local pem_file=$1 repo_url
  checkBinary git
  addcertLoadJenkinsPipelineParams
  repo_url=$(getItsmInstallerRepoUrl)
  cloneItsmInstallerCacertsSparse "${repo_url}"
  cp -f itsmrepo/pipeline/tasks/cacerts "${CACERTS_FILENAME}"
  if [ "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" == "" ]; then
    IS_CACERTS_SSL_TRUSTSTORE_PASSWORD=changeit
  fi
  if ! ${KEYTOOL_BIN} -list -keystore "${CACERTS_FILENAME}" -storepass "${IS_CACERTS_SSL_TRUSTSTORE_PASSWORD}" >/dev/null 2>&1; then
    logError "999" "Checked-out cacerts file could not be opened — check the keystore password for this environment." 1
  fi
  addcertImportPemIntoKeystore "${pem_file}"
  if [ "${ADD_CERT_IMPORTED_COUNT}" -eq 0 ]; then
    logMessage "All certificate(s) from '${pem_file}' are already in cacerts — pipeline/tasks/cacerts was not changed in git."
    return 0
  fi
  validateCacertsFile IS
  if [ "${VALID_CACERTS}" != "0" ]; then
    logError "999" "Updated cacerts file did not pass validation — pipeline/tasks/cacerts was not changed in git." 1
  fi
  if askYesNo "Updated cacerts file is valid — commit and push pipeline/tasks/cacerts to the ITSM installer repository?"; then
    commitPushItsmInstallerCacerts "${pem_file}"
  else
    logMessage "No changes pushed to the ITSM installer repository."
  fi
}

fixAddCert() {
  local PEM_FILE ADD_CERT_GIT=0
  case ${#FIXARGS[@]} in
    2)
      ;;
    3)
      if [ "${FIXARGS[2]}" != "git" ]; then
        logError "999" "Optional third argument for addcert must be 'git' only." 1
      fi
      ADD_CERT_GIT=1
      ;;
    *)
      logError "999" "Usage: bash $0 -f \"addcert /path/to/certificates.pem [git]\"" 1
      ;;
  esac
  PEM_FILE="${FIXARGS[1]/#\~/$HOME}"
  if [ ! -f "${PEM_FILE}" ]; then
    logError "999" "Certificate file '${PEM_FILE}' not found." 1
  fi
  if [ ! -s "${PEM_FILE}" ]; then
    logError "999" "Certificate file '${PEM_FILE}' is empty." 1
  fi
  addcertPreparePemCertDir "${PEM_FILE}"
  addcertPreparePlatformContext
  if [ "${ADD_CERT_GIT}" == "1" ]; then
    fixAddCertToGit "${PEM_FILE}"
  else
    fixAddCertToSecret "${PEM_FILE}"
  fi
  addcertCleanupPemCertDir
}

updateISCacerts() {
  CACERTS_FILENAME="is-sealcacerts"
  cp "${NEWCACERTS}" "${CACERTS_FILENAME}"
  validateCacertsFile IS
  if [ "${VALID_CACERTS}" == "0" ]; then
    if askYesNo "New cacerts file is valid - do you want to replace the cacerts secret?"; then
      replaceISCacertsSecret
      logMessage "cacerts secret in '${IS_NAMESPACE}' namespace replaced with '${NEWCACERTS}'."
    else
        logMessage "No changes made to the cacerts secret in the '${IS_NAMESPACE}' namespace."
    fi
  else
    if askYesNo "New cacerts file may not be valid - are you sure you want to replace the cacerts secret?"; then
      replaceISCacertsSecret
      logMessage "cacerts secret in '${IS_NAMESPACE}' namespace replaced with '${NEWCACERTS}'."
    else
      logMessage "No changes made to the cacerts secret in the '${IS_NAMESPACE}' namespace."
    fi
  fi
}

replaceISCacertsSecret() {
  NOW=$(date +"%Y%m%d%H%M%S")
  BACKUP_FILE="cacerts_backup_${NOW}.yaml"
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get secret cacerts -o yaml > "${BACKUP_FILE}" 2>/dev/null; then
    logMessage "Current cacerts secret saved as ${BACKUP_FILE}."
  fi
  ${KUBECTL_BIN} -n "${IS_NAMESPACE}" delete secret cacerts >/dev/null 2>&1
  ${KUBECTL_BIN} -n "${IS_NAMESPACE}" create secret generic cacerts --from-file=cacerts="${CACERTS_FILENAME}" --dry-run=client -o yaml | ${KUBECTL_BIN} apply -f - >/dev/null 2>&1
}

fixSATRole() {
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get role assisttool-rl >/dev/null 2>&1; then
    logWarning "999" "'assisttool-rl' role is already present in the '${IS_NAMESPACE}' namespace."
  else
    ${KUBECTL_BIN} -n "${IS_NAMESPACE}" create role assisttool-rl --verb=get --verb=list --verb=watch --resource=pods >/dev/null 2>&1
  fi
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get rolebindings assisttool-rlb >/dev/null 2>&1; then
    logWarning "999" "'assisttool-rlb' rolebinding is already present in the '${IS_NAMESPACE}' namespace."
  else
    ${KUBECTL_BIN} -n "${IS_NAMESPACE}" create rolebinding assisttool-rlb --role=assisttool-rl --serviceaccount="${IS_NAMESPACE}":default >/dev/null 2>&1
  fi
  logStatus "Support Assistant Tool 'assisttool-rl' role and 'assisttool-rlb' rolebinding created/updated in the '${IS_NAMESPACE}' namespace."
}

buildRealmJSON() {
  REALM_JSON=$(cat <<EOF
    {
    "domainMapping": {
       "domain": [
         "${IS_PREFIX}.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-smartit.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-sr.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-is.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-restapi.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-atws.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-dwp.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-dwpcatalog.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-vchat.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-chat.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-int.${CLUSTER_DOMAIN}",
         "${IS_PREFIX}-reporting.${CLUSTER_DOMAIN}"
       ]
     },
     "tenantDomain": "${HP_TENANT}",
     "authChain": {
       "idpSaml": [],
       "idpAr": [
         {
           "cspDomains": {
             "domain": [
               ""
             ]
           },
           "id": "ar",
           "order": 1,
           "arHost": "platform-user-ext.${IS_NAMESPACE}",
           "arQueue": 0,
           "arPort": 46262,
           "transformationStrategy": "None",
           "customExpression": ""
         }
       ],
       "idpLdap": [],
       "idpCert": [],
       "idpKerberos": [],
       "idpPreauth": [],
       "idpOidc": [],
       "idpLocalUser": []
     },
     "bypassAllowed": false,
     "tenantLogoutURL": "",
     "sessionQuota": 0,
     "forceLogoutOnReachQuota": true,
     "singleLogOut": false,
     "useCaptcha": false,
     "onAuthWebhook": "",
     "tenantName": "${IS_PREFIX}"
    }
EOF
  )
}

fixCacerts() {
  if [ ${#FIXARGS[@]} -ne 2 ]; then
    logError "999" "Usage: bash $0 -f \"cacerts /path/to/new/cacerts-file\"" 1
  fi
  NEWCACERTS="${FIXARGS[1]/#\~/$HOME}" # convert ~ to path if used
  if [ ! -f "${NEWCACERTS}" ]; then
    logError "999" "New cacerts file '${NEWCACERTS}' not found." 1
  fi
  checkToolVersion kubectl
  getVersions
  setVarsFromPlatform
  getDomain
  buildISAliasesArray
  updateISCacerts
}

fixSSORealm() {
  REALM_NAME="${IS_CUSTOMER_SERVICE}-${IS_ENVIRONMENT}"
  checkToolVersion kubectl
  getVersions
  setVarsFromPlatform
  getRSSODetails
  getDomain
  getTenantDetails
  HP_TENANT_ID="${HP_TENANT#*.}"
  if [ "${HP_SM_PLATFORM_CORE}"  == "no" ]; then
    deleteTCTLJob
    deployTCTL "get tenant ${HP_TENANT_ID} -o json"
    getTCTLOutput full
    deleteTCTLJob
    # Get JSON from tctl pod output
    TMP_JSON=$(extractTctlJsonFromLogText <<< "${TCTL_OUTPUT}")
  fi

  buildRealmJSON

  if [ "${HP_SM_PLATFORM_CORE}"  == "no" ]; then
    REALM_AUTH_TYPE=$(echo "${TMP_JSON}" | ${JQ_BIN} -r '.auth_context.type')
    if [ "${REALM_AUTH_TYPE}" == "OIDC" ]; then # INTEROPS has been run so portal alias should be in Application Domains
      REALM_JSON=$(echo "${REALM_JSON}" | ${JQ_BIN} --arg ND "${PORTAL_HOSTNAME}" '.domainMapping.domain += [$ND]')
    fi
  fi
  if ${CURL_BIN} -sk -X GET "${RSSO_URL}"/api/v1.1/realms/"${REALM_NAME}" -H "Authorization: RSSO ${RSSO_TOKEN}" | ${JQ_BIN} | grep -q "realm does not exist" ; then
    CURL_ACTION=POST
    URL_SUFFIX=""
    logMessage "Creating new realm '${REALM_NAME}'."
  else
    CURL_ACTION=PUT
    URL_SUFFIX="/${REALM_NAME}"
    logMessage "Updating existing realm '${REALM_NAME}'."
  fi

  ${CURL_BIN} -sk -X "${CURL_ACTION}" "${RSSO_URL}/api/v1.1/realms${URL_SUFFIX}" \
    -H "Content-Type: application/json" \
    -H "Authorization: RSSO ${RSSO_TOKEN}" \
    -d "${REALM_JSON}" >"${HITT_ERR_FILE}" 2>&1
}

updateJenkinsKubeconfig() {
  SCRIPT="import com.cloudbees.plugins.credentials.*
    import com.cloudbees.plugins.credentials.domains.*
    import jenkins.model.*
    import org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl
    import hudson.util.Secret
    import com.cloudbees.plugins.credentials.SecretBytes
    def kubeconfigContentBase64 = '''${KUBECONFIG_B64}'''
    def secretBytes = SecretBytes.fromBytes(kubeconfigContentBase64.decodeBase64())
    def store = Jenkins.instance
        .getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]
        .getStore()
    def existing = CredentialsProvider.lookupCredentials(
        FileCredentialsImpl.class,
        Jenkins.instance,
        null,
        null
    ).find { it.id == 'kubeconfig' }
    if (existing) {
        store.removeCredentials(Domain.global(), existing)
    }
    def fileCredential = new FileCredentialsImpl(
        CredentialsScope.GLOBAL,
        'kubeconfig',                   // ID
        'Kubeconfig file from script',  // Description
        'kubeconfig',                   // File name
        secretBytes                     // SecretBytes content
    )
    store.addCredentials(Domain.global(), fileCredential)"
  runJenkinsScript "${SCRIPT}" >/dev/null
}

checkValidKubeconfig() {
  if [ ! -f "${1}" ]; then
    logError "999" "kubeconfig file '${1}' not found." 1
  fi
  if ! ${KUBECTL_BIN} --kubeconfig="${1}" version > /dev/null 2>&1; then
    logError "999" "'kubectl version' command returned an error - is '${1}' a valid kubeconfig file?" 1
  fi
}

fixJenkinsKubeconfig() {
  case "${#FIXARGS[@]}" in
    2)
      KUBECONFIG_FILE="${HOME}/.kube/config"
      ;;
    3)
      KUBECONFIG_FILE="${FIXARGS[2]/#\~/$HOME}" # convert ~ to path if used
      ;;
    *)
      logError "999" "Usage: bash $0 -f \"jenkins kubeconfig\" (uses ~/.kube/config) OR \"jenkins kubeconfig /path/to/kubeconfig\"" 1
      ;;
  esac
  checkValidKubeconfig "${KUBECONFIG_FILE}"
  encodeKubeconfig "${KUBECONFIG_FILE}"
  if askYesNo "Do you want to update the Jenkins kubeconfig credential with '${KUBECONFIG_FILE}'?"; then
    updateJenkinsKubeconfig
    logMessage "Jenkins kubeconfig credential updated with '${KUBECONFIG_FILE}'."
  else
    logMessage "No changes made to the Jenkins kubeconfig credential."
  fi
}

encodeKubeconfig() {
  KUBECONFIG_B64=$(${BASE64_BIN} -w 0 "${1}")
}

fixJenkinsScriptApproval () {
  SCRIPT='import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval
    scriptApproval = ScriptApproval.get()
    alreadyApproved = new HashSet<>(Arrays.asList(scriptApproval.getApprovedSignatures()))
    approveSignature("method org.jenkinsci.plugins.workflow.support.steps.build.RunWrapper getRawBuild")
    approveSignature("method hudson.model.Run getLog")
    scriptApproval.save()
    void approveSignature(String signature) {
        if (!alreadyApproved.contains(signature)) {
           scriptApproval.approveSignature(signature)
        }
    }'
  runJenkinsScript "${SCRIPT}"
  logMessage "Updated Jenkins to approve scripts required by deployment pipelines."
}

fixJenkinsPipelineLibs() {
  PIPELINE_LIBS=(
    "JENKINS-27413-workaround-library,jenkins-workaround,JENKINS-27413-workaround-library.git,true"
    "pipeline-framework,pipeline-framework,pipeline-framework.git,false"
  )

  for pl in "${PIPELINE_LIBS[@]}"; do
    PLNAME=$(echo "${pl}" | awk -F',' '{ print $1 }')
    PLDIR=$(echo "${pl}" | awk -F',' '{ print $2 }')
    PLGIT=$(echo "${pl}" | awk -F',' '{ print $3 }')
    PLIMPLICIT=$(echo "${pl}" | awk -F',' '{ print $4 }')

    if [ ${#FIXARGS[@]} -eq 2 ]; then
      PLPATHS_ARRAY=($(find ~ -type d -name "${PLGIT}" 2>/dev/null))
      PATH_TO_PL=""
      if [ ${#PLPATHS_ARRAY[@]} -eq 0 ]; then
        logError "999" "Unable to find the pipeline libraries git directory - please use 'bash $0 -f \"jenkins pipelinelibs /path/to/LIBRARY_REPO\"'". 1
      elif [ ${#PLPATHS_ARRAY[@]} -eq 1 ]; then
        PATH_TO_PL="${PLPATHS_ARRAY[0]}"
        logMessage "Auto-selected '${PLNAME}' git directory: ${PATH_TO_PL}" 1
      else
        logStatus "Select the '${PLNAME}' git directory:"
        while [ "${PATH_TO_PL}" == "" ]; do
            PATH_TO_PL=$(selectFromArray PLPATHS_ARRAY)
        done
      fi
    fi

    if [ ${#FIXARGS[@]} -eq 3 ]; then
      PL_BASE_DIR="${FIXARGS[2]/#\~/$HOME}"
      PATH_TO_PL="${PL_BASE_DIR}/${PLDIR}/${PLGIT}"
      if [ -d "${PATH_TO_PL}" ]; then
        logMessage "'${PLNAME}' pipeline library git directory found at '${PATH_TO_PL}'." 1
      else
        logError "999" "'${PLNAME}' git directory not found at '${PATH_TO_PL}'." 1
      fi
    fi

    updateJenkinsPipelineLibrary "${PLNAME}" "ssh://${USER}@${LONG_HOSTNAME}${PATH_TO_PL}" "${PLIMPLICIT}"
    logMessage "Jenkins '${PLNAME}' pipeline library updated."

  done
}

updateJenkinsPipelineLibrary() {
  SCRIPT="import jenkins.model.*
    import jenkins.plugins.git.GitSCMSource
    import org.jenkinsci.plugins.workflow.libs.*
    def libraryName = '${1}'
    def repoUrl = '${2}'
    def defaultVersion = 'master'
    def credentialsId = ''
    def implicit = ${3}
    def jenkins = Jenkins.instance
    def globalLibraries = jenkins.getDescriptorByType(GlobalLibraries.class)
    def scmSource = new GitSCMSource(repoUrl)
    scmSource.credentialsId = credentialsId
    def retriever = new SCMSourceRetriever(scmSource)
    def existingLibrary = globalLibraries.libraries.find { it.name == libraryName }
    if (existingLibrary) {
      globalLibraries.libraries.remove(existingLibrary)
    }
    def newLibrary = new LibraryConfiguration(libraryName, retriever)
    newLibrary.setDefaultVersion(defaultVersion)
    newLibrary.setImplicit(implicit)
    globalLibraries.libraries += newLibrary
    jenkins.save()"
  runJenkinsScript "${SCRIPT}"
}

updateJenkinsUserCredentials() {
  JENKINS_USER_CREDS=("github" "ansible_host" "ansible" "git")
  for cred in "${JENKINS_USER_CREDS[@]}"; do
    SCRIPT="import com.cloudbees.plugins.credentials.*
      import com.cloudbees.plugins.credentials.domains.*
      import com.cloudbees.plugins.credentials.impl.*
      import com.cloudbees.plugins.credentials.common.*
      import hudson.util.Secret
      import jenkins.model.Jenkins
      def credentialsId = '${cred}'
      def newUsername = '${GIT_USER}'
      def newPassword = '${GIT_USER_PASSWORD}'
      def newDescription = '${cred}'
      def credentialsStore = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
      def domain = Domain.global()
      def existing = CredentialsProvider.lookupCredentials(
          StandardUsernamePasswordCredentials.class,
          Jenkins.instance,
          null,
          null
      ).find { it.id == credentialsId }
            if (existing) {
          def updated = new UsernamePasswordCredentialsImpl(
              CredentialsScope.GLOBAL,
              credentialsId,
              newDescription,
              newUsername,
              newPassword
          )
          credentialsStore.updateCredentials(domain, existing, updated)
      } else {
          def newCred = new UsernamePasswordCredentialsImpl(
              CredentialsScope.GLOBAL,
              credentialsId,
              newDescription,
              newUsername,
              newPassword
          )
          credentialsStore.addCredentials(domain, newCred)
      }"
    runJenkinsScript "${SCRIPT}" >/dev/null
    logMessage "Updated Jenkins '${cred}' credentials."
  done
}

updateJenkinsSecretTextCredentials() {
  SCRIPT="import jenkins.model.Jenkins
  import com.cloudbees.plugins.credentials.domains.Domain
  import com.cloudbees.plugins.credentials.CredentialsScope
  import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl
  import com.cloudbees.plugins.credentials.CredentialsProvider
  import hudson.util.Secret
  def credentialsId = 'password_vault_apikey'
  def secretValue = ''
  def description = 'password_vault_apikey'
  def instance = Jenkins.instance
  def domain = Domain.global()
  def store = instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
  def existing = CredentialsProvider.lookupCredentials(
      StringCredentialsImpl.class,
      instance,
      null,
      null
  ).find { it.id == credentialsId }
  if (existing) {
      def updated = new StringCredentialsImpl(
          CredentialsScope.GLOBAL,
          credentialsId,
          description,
          Secret.fromString(secretValue)
      )
      store.updateCredentials(domain, existing, updated)
  } else {
      def secretText = new StringCredentialsImpl(
          CredentialsScope.GLOBAL,
          credentialsId,
          description,
          Secret.fromString(secretValue)
      )
      store.addCredentials(domain, secretText)
  }
  instance.save()"
  runJenkinsScript "${SCRIPT}" >/dev/null
  logMessage "Updated Jenkins password_vault_apikey credentials."
}

updateJenkinsSecretFileCredentials() {
  SCRIPT="import jenkins.model.*
    import com.cloudbees.plugins.credentials.*
    import com.cloudbees.plugins.credentials.domains.*
    import org.jenkinsci.plugins.plaincredentials.impl.FileCredentialsImpl
    import hudson.util.Secret
    import com.cloudbees.plugins.credentials.SecretBytes
    def credentialsId = 'TOKENS'
    def description = 'tokens.json'
    def fileName = 'tokens.json'
    def fileContent = ''
    def fileBytes = SecretBytes.fromBytes(fileContent.getBytes('UTF-8'))
    def instance = Jenkins.instance
    def domain = Domain.global()
    def store = instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0].getStore()
    def existing = CredentialsProvider.lookupCredentials(
        FileCredentialsImpl.class,
        instance,
        null,
        null
    ).find { it.id == credentialsId }
    if (existing) {
        def updated = new FileCredentialsImpl(
            CredentialsScope.GLOBAL,
            credentialsId,
            description,
            fileName,
            fileBytes
        )
        store.updateCredentials(domain, existing, updated)
    } else {
        def fileSecret = new FileCredentialsImpl(
            CredentialsScope.GLOBAL,
            credentialsId,
            description,
            fileName,
            fileBytes
        )
      store.addCredentials(domain, fileSecret)
    }
    instance.save()"
  runJenkinsScript "${SCRIPT}" >/dev/null
  logMessage "Updated Jenkins TOKENS credentials."
}

fixJenkinsCredentials() {
  if ! which sshpass  > /dev/null 2>&1 ; then
    logError "999" "The 'sshpass' command was not found but is required to enable Jenkins credentials password validation. Please install 'sshpass'." 1
  fi
  logStatus "Please enter your GIT user password:"
  read -r -s -p "GIT user password : " GIT_USER_PASSWORD
  if ! sshpass -p "${GIT_USER_PASSWORD}" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new "${GIT_USER}@${LONG_HOSTNAME}" whoami >/dev/null 2>&1 ; then
    logError "999" "The GIT user password is incorrect." 1
  fi
  echo ""
  updateJenkinsUserCredentials
  updateJenkinsSecretTextCredentials
  updateJenkinsSecretFileCredentials
}

testSSH() {
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no "${GIT_USER}@${1}" "echo success" 2>/dev/null | grep -q success; then
        logMessage "Passwordless 'ssh ${GIT_USER}@${1}' succeeded."
    else
        logError "999" "Passwordless 'ssh ${GIT_USER}@${1}' failed."
    fi
}

fixSSH() {
  HOME_DIR=$(getent passwd ${1} | cut -d: -f6)
  GIT_HOME_DIR=$(getent passwd ${GIT_USER} | cut -d: -f6)
  SSH_DIR="${HOME_DIR}/.ssh"
  KEY_FILE="${SSH_DIR}/id_rsa"
  AUTHORIZED_KEYS="${GIT_HOME_DIR}/.ssh/authorized_keys"
  chmod 700 "${GIT_HOME_DIR}"
  # Set correct perms or create ~/.ssh and key files
  if [ -d "${SSH_DIR}" ]; then
    chmod 700 "${SSH_DIR}"
  else
    mkdir -p -m 700 "${SSH_DIR}"
  fi
  if [ -f "${KEY_FILE}" ]; then
    chmod 600 "${KEY_FILE}"
    chmod 644 "${KEY_FILE}.pub"
  else
    ssh-keygen -t rsa -b 4096 -f "${KEY_FILE}" -N "" -q
  fi
  PUB_KEY=$(cat "${KEY_FILE}.pub")
  # Ensure authorized_keys file exists
  touch "${AUTHORIZED_KEYS}"
  chmod 600 "${AUTHORIZED_KEYS}"
  # Add key if not already in authorized_keys
  if ! grep -qF "{$PUB_KEY}" "${AUTHORIZED_KEYS}"; then
      echo "${PUB_KEY}" >> "${AUTHORIZED_KEYS}"
  fi
  testSSH "${SHORT_HOSTNAME}"
  testSSH "${LONG_HOSTNAME}"
}

triggerHelixDryRun() {
  SCRIPT="import jenkins.model.*
    import hudson.model.*
    import org.jenkinsci.plugins.workflow.job.WorkflowJob
    def jobList = [
      'HELIX_CONFIGURE_ITSM',
      'HELIX_GENERATE_CONFIG',
      'HELIX_ITSM_INTEROPS',
      'HELIX_NON_PLATFORM_DEPLOY',
      'HELIX_ONPREM_DEPLOYMENT',
      'HELIX_PLATFORM_DEPLOY',
      'HELIX_POST_DEPLOY_CONFIG',
      'HELIX_SMARTAPPS_DEPLOY',
      'SUPPORT_ASSISTANT_TOOL',
      'HELIX_RESTART',
      'HELIX_DR',
      'HELIX_RLS_IMPLEMENTATION',
      'HELIX_DB_REFRESH',
      'HELIX_NON_PLATFORM_UPDATE',
      'HELIX_PLATFORM_UPDATE',
      'HELIX_FULL_STACK_UPGRADE',
      'HELIX_PLATFORM_UPGRADE',
      'HELIX_NON_PLATFORM_UPGRADE'
      ]
    def jenkins = Jenkins.instance
    jobList.each { jobName ->
      def job = jenkins.getItemByFullName(jobName)
      if (job == null) { return }
      if (!(job instanceof WorkflowJob)) { return }
      def causeAction = new CauseAction(new Cause.UserIdCause())
      def future = job.scheduleBuild2(0, causeAction)
      def build = future.get()
    }"
  logMessage "Started dry runs of Helix deployment pipelines..."
  runJenkinsScript "${SCRIPT}"
}

isJenkinsInCluster() {
  if [ -n "${K8S_JENKINS}" ]; then return 0; fi
  # -g needed to allow [] in url
  JENKINS_AGENTS=($(${CURL_BIN} -gks "${JENKINS_URL}/computer/api/json?tree=computer[displayName]" | ${JQ_BIN} -r '.computer[].displayName'))
  if printf '%s\0' "${JENKINS_AGENTS[@]}" | grep -Fqz -- 'jenkins-agent'; then
    K8S_JENKINS=1
    return 0
  else
    return 1
  fi
}

fixJenkins() {
  checkJenkinsIsRunning 1
  #getJenkinsCrumb
  if isJenkinsInCluster && ([[ "${FIXARGS[1]}" != "kubeconfig" ]] && [[ "${FIXARGS[1]}" != "dryrun" ]]); then
    logError "999" "Jenkins fixmode '${FIXARGS[1]}' is not supported when Jenkins is running in the cluster - only 'kubeconfig' and 'dryrun' are valid."
  fi
  case "${FIXARGS[1]}" in
    kubeconfig)
      fixJenkinsKubeconfig
      ;;
    scriptapproval)
      fixJenkinsScriptApproval
      ;;
    pipelinelibs)
      fixJenkinsPipelineLibs
      ;;
    credentials)
      fixJenkinsCredentials
      ;;
    dryrun)
      triggerHelixDryRun
      ;;
    nodes)
      fixJenkinsNodes
      ;;
    plugins)
      fixJenkinsPlugins
      ;;
    all)
      fixJenkinsCredentials
      fixJenkinsPipelineLibs
      fixJenkinsScriptApproval
      fixJenkinsKubeconfig
      ;;
    *)
      logError "999" "'${FIXARGS[1]}' is not a valid jenkins fix option." 1
      ;;
  esac
}

fixJenkinsPlugins() {
  logMessage "Getting list of Jenkins recommended plugins..."
  JENKINS_RECOMMENDED_PLUGINS_URL=https://raw.githubusercontent.com/jenkinsci/jenkins/refs/heads/master/core/src/main/resources/jenkins/install/platform-plugins.json
  JENKINS_RECOMMENDED_PLUGINS_XML=$(${CURL_BIN} -s "${JENKINS_RECOMMENDED_PLUGINS_URL}" | ${JQ_BIN} -r '
  "<jenkins>",
  (.[] | .plugins[] | "    <install plugin=\"\(.name)@latest\" />"),
  "</jenkins>"
')

  if [ $(echo "${JENKINS_RECOMMENDED_PLUGINS_XML}" | wc -l) == "0" ]; then
    logError "999" "Failed to get list of Jenkins recommended plugins from '${JENKINS_RECOMMENDED_PLUGINS_URL}'" 1
  fi
  logMessage "Installing Jenkins recommended plugins..."
  ${CURL_BIN} --max-time 3 -b .cookies -skv -H "Jenkins-Crumb:${JENKINS_CRUMB}" -d "${JENKINS_RECOMMENDED_PLUGINS_XML}" -H "Content-Type: text/xml" "${JENKINS_URL}/pluginManager/installNecessaryPlugins" 2>>${HITT_ERR_FILE}
}

fixJenkinsNodes() {
  addJenkinsNodeLabel
}

addJenkinsNodeLabel() {
  SCRIPT="import jenkins.model.*
    import hudson.model.*
    def targetLabel = 'ansible-master'
    def newLabel = 'ansible-master-latest'
    Jenkins.instance.nodes.each { node ->
        if (node.getAssignedLabels().any { it.name == targetLabel }) {
            def currentLabels = node.getLabelString().tokenize(' ').toSet()
            if (!currentLabels.contains(newLabel)) {
                currentLabels << newLabel
                node.setLabelString(currentLabels.join(' '))
            }
        }
    }"
  logMessage "Adding missing node label..."
  runJenkinsScript "${SCRIPT}" >/dev/null
}

generateISDbID() {
  # Create the source string (all uppercase)
  if [ -z "${IS_DB_TYPE}" ] || [ -z "${IS_DATABASE_HOST_NAME}" ] || [ -z "${IS_AR_DB_NAME}" ]; then
    return
  fi
  case "${IS_DB_TYPE^^}" in
    MSSQL)
      DB_TYPE="SQL -- SQL SERVER"
      ;;
    ORACLE)
      DB_TYPE="SQL -- ORACLE"
      ;;
    POSTGRES)
      DB_TYPE="POSTGRESQL"
      ;;
    *)
      logError "999" "Invalid DB_TYPE '${IS_DB_TYPE}' - valid options are mssql|oracle|postgres." 1
      ;;
  esac
  IS_DBID_SOURCE="${DB_TYPE^^}|${IS_DATABASE_HOST_NAME^^}|${IS_AR_DB_NAME^^}"
  # Generate SHA-256 hash and encode to base64 without padding
  IS_DBID=$(printf "%s" "${IS_DBID_SOURCE}" | ${OPENSSL_BIN} dgst -sha256 -binary | ${BASE64_BIN} | tr -d '=')
  logMessage "IS DB ID will be '${IS_DBID}' from '${IS_DBID_SOURCE}'."
}

getISDbID() {
  initISAdminREST
  IS_DBID=$(getISServerInfo dbId)
  logMessage "DB ID for this system is '${IS_DBID}'."
}

getISJWTToken() {
  local IS_USERNAME
  local IS_PASSWORD
  IS_USERNAME="${1}"
  IS_PASSWORD="${2}"
  if [ -n "${IS_USERNAME}" ] && [ -z "${IS_PASSWORD}" ]; then
    read -r -s -p "${IS_USERNAME} password : " IS_PASSWORD
  fi
  if [ -z "${IS_USERNAME}" ]; then
    IS_USERNAME=hannah_admin
  fi
  checkToolVersion kubectl
  getVersions
  getDomain
  buildISAliasesArray
  if [ "${IS_USERNAME}" == "hannah_admin" ]; then
    getISAdminCreds
  else
    IS_USER="${IS_USERNAME}"
    IS_PASSWD="${IS_PASSWORD}"
    getISJWT
  fi
  logStatus "Getting IS REST API JWT for user '${IS_USERNAME}'..."
  if ! getISJWT; then
    logError "999" "Failed to authenticate user '${IS_USERNAME}' - can't get JWT." 1
  fi
  printf 'ARJWT="%s"\n' "${ARJWT}"
}

applyARLicense() {
  local HTTP_RESPONSE
  local HTTP_CODE
  IS_LICENSE_KEY="${FIXARGS[1]^^}"
  IS_LICENSE_EXPIRY=""
  # Validate inputs
  if [[ ! "${IS_LICENSE_KEY}" =~ ^[A-Z]{3}-[0-9]{6}(-[A-Z]{2}-[0-9]{3})?$ ]]; then
    logError "999" "Invalid license key format '${FIXARGS[1]}'. Expected format is 'XXX-nnnnnn' or 'XXX-nnnnnn-XX-nnn' where X is a letter and n is a number."
    INVALID_IS_LICENSE=1
  else
    IS_LICENSE_JSON="{\"values\":{\"License Type\":\"AR Server\",\"Number of Licenses\":1,\"Key\":\"${IS_LICENSE_KEY}\"}}"
  fi
  if [ -n "${FIXARGS[2]}" ]; then
    IS_LICENSE_EXPIRY="${FIXARGS[2]}"
    if [[ ! "${FIXARGS[2]}" =~ ^(0[1-9]|[12][0-9]|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-[0-9]{2}$ ]]; then
      logError "999" "Invalid license expiry date format '${FIXARGS[2]}'. Expected format is 'DD-Mon-YY' - eg 01-Feb-27."
      INVALID_IS_LICENSE=1
    else
      IS_LICENSE_JSON="{\"values\":{\"License Type\":\"AR Server\",\"Number of Licenses\":1,\"Key\":\"${IS_LICENSE_KEY}\",\"Expiration Date\":\"${IS_LICENSE_EXPIRY}\"}}"
    fi
  fi
  [[ ! -z "${INVALID_IS_LICENSE+x}" ]] && exit
  initISAdminREST
  IS_LICENSE_TYPE=$(getISServerInfo licensetype)
  logMessage "Current server license type is '${IS_LICENSE_TYPE}'."
  # is license already present?
  NUM_LICS=$(${CURL_BIN} -sk "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/arsys/v1/entry/AR%20System%20Licenses?q=%27Key%27%3D%22${IS_LICENSE_KEY}%22&fields=values(Key)" -H "Authorization: AR-JWT ${ARJWT}" | ${JQ_BIN} -r '.entries |length')
  if [[ $NUM_LICS -ne 0 ]]; then
    logError "999" "License with key '${IS_LICENSE_KEY}' is already present." 1
  fi
  HTTP_RESPONSE=$(mktemp)
  HTTP_CODE=$(${CURL_BIN} -o "${HTTP_RESPONSE}" -sk -w "%{http_code}" -X POST "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/arsys/v1/entry/AR%20System%20Licenses" -H "Authorization: AR-JWT ${ARJWT}" -H 'Content-Type: application/json' -d "${IS_LICENSE_JSON}" 2>/dev/null)
  case "${HTTP_CODE}" in
    200|201)
      logMessage "License applied - ${IS_LICENSE_JSON}"
      ;;
    *)
      logError "999" "Failed to apply license - '${HTTP_CODE}'."
      cat "${HTTP_RESPONSE}" | sed 's/^/        /'
      echo
      ;;
  esac
  rm -f "${HTTP_RESPONSE}"
}

askYesNo() {
  local prompt="$1"
  local response

  while true; do
    read -rp "${prompt} [y/n]: " response
    case "${response}" in
      y|Y) return 0 ;;  # Yes: return success
      n|N) return 1 ;;  # No: return failure
      *) echo "Please enter 'y' or 'n'." ;;
    esac
  done
}

activateHP() {
  checkToolVersion kubectl
  getVersions
  if compare "${HP_VERSION%.*} >= 25.4" ; then
    logMessage "The activatehp fix is not valid for Helix Platform versions 25.4.00 and above."
    exit
  fi
  setVarsFromPlatform
  getRSSODetails
  getDomain
  getTenantDetails
  HP_TENANT_ID="${HP_TENANT#*.}"
  if ! isTenantActivated ; then
    ${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PG_POD}" -- psql -d ade_rsso -U postgres -tc "update localuser set password = '\x020a7e17c23b9cb42174e31d1d39085f305bdbab57544b163e1c2be70c7523b43eb1f1e8b092ed5b13f05aff838d32141181892e14bbfdbd75ab235640adfc30731f9c7f72d24f2a2ecba2fa22d2dd50ca85020d15213956c22f09e87f76fa4398' where login = 'hannah_admin' and realm='${HP_TENANT}' and status = 'REG_PENDING'" > /dev/null 2>&1
    ${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PG_POD}" -- psql -d ade_rsso -U postgres -tc "update localuser set status = '${HP_TENANT_ACTIVATED_STATUS}' where login = 'hannah_admin' and realm='${HP_TENANT}' and status = 'REG_PENDING'" > /dev/null 2>&1
    logMessage "Tenant '${HP_TENANT}' activated."
    exit
  fi
}

resetSSOPasswd() {
  PG_POD=$(getPodNameByLabel "${HP_NAMESPACE}" "application=patroni,data=pool")
  SSO_ADMIN_TID=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PG_POD}" -- psql -d ade_rsso -U postgres -tc "select tid from AdminUsers where loginid = 'Admin' and tid = '00000000-0000-0000-0000-000000000000';" 2>/dev/null )
  if echo "${SSO_ADMIN_TID}" | grep -q "00000000-0000-0000-0000-000000000000" ; then
    if askYesNo "Do you want to reset the SSO admin password?"; then
      ${KUBECTL_BIN} -n "${HP_NAMESPACE}" exec -ti "${PG_POD}" -- psql -d ade_rsso -U postgres -tc "update adminusers set Password = '3a544f348f1ed1ec7bdfbfb41cb3f752', blocked=0  where LoginId = 'Admin' and tid = '00000000-0000-0000-0000-000000000000';" >/dev/null 2>&1
      logMessage "SSO admin user password has been reset to the default value."
    else
      logMessage "SSO admin user password has not been changed."
    fi
  else
    logError "999" "SSO admin user not found - no changes made."
  fi
}

validateSSHPermissions() {
  SSH_DIR="$HOME/.ssh"
  SSH_ERROR=0
  local dir
  logMessage "Validating directory and file permissions for SSH..."

  if [ ! -d "$SSH_DIR" ]; then
    logError "235" "SSH directory '$SSH_DIR' does not exist. Please see the product documentation for the steps to set up ssh for the git user."
    return
  fi

  for dir in "$HOME" "$SSH_DIR"; do
    if [ $(find "$dir" -maxdepth 0 -perm /go=w | wc -l) != "0" ]; then
      logError "249" "'$dir' directory should not have write permssion for group/other - ssh may not work."
      SSH_ERROR=1
    fi
    if [ "$(stat -c "%U" "$dir")" != "${GIT_USER}" ]; then
      logError "249" "Owner of '$dir' is not '${GIT_USER}'."
      SSH_ERROR=1
    fi
  done

  # Check authorized_keys
  SSH_AUTH_KEYS="$SSH_DIR/authorized_keys"
  if [ -f "${SSH_AUTH_KEYS}" ]; then
    if [ "$(stat -c "%a" "${SSH_AUTH_KEYS}")" != "600" ]; then
      logError "249" "Permissions on '${SSH_AUTH_KEYS}' should be 600."
      SSH_ERROR=1
    fi
    if [ "$(stat -c "%U" "${SSH_AUTH_KEYS}")" != "${GIT_USER}" ]; then
      logError "249" "Owner of '${SSH_AUTH_KEYS}' is not '${GIT_USER}'."
      SSH_ERROR=1
    fi
  fi

  # Check private keys
  for key in "$SSH_DIR"/id_*; do
    [ -f "$key" ] || continue
    [[ "$key" == *.pub ]] && continue
    if [ "$(stat -c "%a" "$key")" != "600" ]; then
      logError "249" "Private key '$key' should have 600 permissions."
      SSH_ERROR=1
    fi
  done

  # Check public keys
  for pubkey in "$SSH_DIR"/*.pub; do
    [ -f "$pubkey" ] || continue
    if [ "$(stat -c "%a" "$pubkey")" != "644" ]; then
      logError "249" "Public key '$pubkey' should have 644 permissions."
      SSH_ERROR=1
    fi
  done

  if [ "${SSH_ERROR}" -eq 0 ]; then
    logMessage "SSH permissions and ownership are valid." 1
  else
    logError "247" "One or more SSH permission issues detected. Review permissions on the files/directories reported in the errors."
  fi
}

getPipelineConsoleOutput() {
  ${CURL_BIN} -skf "${JENKINS_URL}/job/${1^^}/lastBuild/consoleText"
}

logK8sNodeDetails() {
  local OUTPUT_FILE=k8s-nodes.txt
  local node
  # Check if the user can list nodes
  if ${KUBECTL_BIN} auth can-i list nodes --all-namespaces > /dev/null 2>&1; then
      ${KUBECTL_BIN} get nodes --no-headers -o custom-columns=":metadata.name" | while read -r node; do
          ${KUBECTL_BIN} describe node "$node" >> "$OUTPUT_FILE"
      done
  fi
}

getPodConditionTime() {
    local CONDITION="$1"
    local NAMESPACE_NAME="$2"
    local POD_NAME="$3"
    ISO_TIME=$(${KUBECTL_BIN} -n "${NAMESPACE_NAME}" get pod "${POD_NAME}" -o json | ${JQ_BIN} ".status.conditions[] | select(.type == \"${CONDITION}\" and .status == \"True\") | .lastTransitionTime" | tr -d '"\n')
    date -d ${ISO_TIME} +%s
}

getPodStartupTime() {
  POD_SCHEDULED_EPOCH=$(getPodConditionTime "PodScheduled" "${1}" "${2}")
  POD_READY_EPOCH=$(getPodConditionTime "Ready" "${1}" "${2}")
  echo $(( POD_READY_EPOCH - POD_SCHEDULED_EPOCH ))
}

logPlatformFTSStartTime() {
  if ${KUBECTL_BIN} -n "${IS_NAMESPACE}" get pod platform-fts-0 -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True &> /dev/null; then
    STARTUP_SECS=$(getPodStartupTime "${IS_NAMESPACE}" platform-fts-0)
    STARTUP_TIME=$(printf "%s" "$(date -u -d "@${STARTUP_SECS}" +%T)")   # prints HH:MM:SS (UTC))
  else
    return
  fi
  logMessage "platform-fts-0 pod startup time: ${STARTUP_TIME}"
  if [ "${STARTUP_SECS}" -gt 900 ]; then
    logWarning "044"  "platform-fts-0 pod took more than 15 minutes to start - possible db latency or performance issue."
  fi
}

showFixHelp() { # fix mode help
  echo "HITT fix mode options - see https://bit.ly/hittfix"
  echo .
  echo 'Usage: bash hitt.sh -f "<fixmode> [fixmode options]"'
  echo -e "
    \tssh \t\t| Set up/update passwordless ssh for the git user.
    \trealm \t\t| Create/update the Helix Service Management realm in SSO.
    \tcacerts \t| Update the cacerts secret in the Helix IS namespace with a new file.
    \taddcert \t| Add PEM certificate(s) to the IS cacerts secret, or with 'git' to pipeline/tasks/cacerts. Args: /path/to/certificates.pem [git]
    \tsat \t\t| Create the assisttool-rl role and assisttool-rlb role-binding required by the Support Assistant Tool.
    \tarlicense \t| Apply an Innovation Suite/AR server license to the system via the REST API.
    \tresetssopwd \t| Resets the Helix SSO admin user password to the BMC default value.
    \tjenkins \t| Jenkins specific fixes - see below.
    \thelp \t\t| Show this list.
    "
  echo -e '\tJenkins fixmode options:'
  echo -e "
    \tscriptapproval \t| Approves the scripts required by the deployment pipelines.
    \tpipelinelibs \t| Create/update the Global Trusted Pipeline Library definitions.
    \tcredentials \t| Create/update all the required credentials, except kubeconfig - see the 'kubeconfig' option.
    \tkubeconfig \t| Create/update the kubeconfig credential with a new kubeconfig file.
    \tall \t\t| Runs all of the Jenkins fixes except for 'dryrun'.
    \tdryrun \t\t| Trigger a dry run of all the HELIX pipelines.
    "
}

showUtilHelp() { # utility mode help
  echo "HITT utility mode options - see https://bit.ly/hittutil"
  echo .
  echo 'Usage: bash hitt.sh -u "<utilmode> [utilmode options]"'
  echo -e "
    \tget secret \t| Decode Kubernetes secret .data (binary keys saved as files). Args: SECRETNAME [NAMESPACE]
    \tget configmap \t| Export ConfigMap .data and .binaryData keys to files in a new directory (named after the ConfigMap), or with -v list key names only. Args: CM_NAME [NAMESPACE]
    \tget dbid \t| Display the database ID (DBID) for the system - used for licensing.
    \tget jwt \t| Print AR-JWT for IS REST API. Optional: USERNAME PASSWORD (default hannah_admin from cluster).
    \tget forms \t| Search AR forms by keyword; prints form name and Schema ID. Args: KEYWORD (use quotes for multi-word, e.g. -u \"get forms AR System\")
    \tget fields \t| List fields on a form by Schema ID; optional keyword filters field names. Args: SCHEMAID [KEYWORD]
    \tsql \t\t| Run an AR SQL query via IS REST API (raw JSON). Args: SQL_QUERY (quote the whole -u string)
    \tgendbid \t| Generate DBID from DB_TYPE DATABASE_HOST_NAME AR_DB_NAME.
    \tcheckpat \t| Validate Docker Hub username and PAT. Args: [USERNAME] [PAT] — omit both to use bmc-dtrhub from HP namespace or be prompted.
    \timagels \t| List tags for a container image repository (requires skopeo). Args: IMAGE — name under docker.io/bmchelix/ or full registry/host/path/repo.
    \tcheckrbac \t| Validate Kubernetes RBAC for HITT. Args: [hitt|deploy|all] (default: hitt). Use -v for each permission checked. Legacy alias: authcheck (= checkrbac hitt).
    \thelp \t\t| Show this list.
    "
}

showConsoleLogHelp() { # -o console log options help
  echo "HITT console log options - see https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-pipeline-mode.md#view-logs-from-the-deployment-engine--o"
  echo .
  echo 'Usage: bash hitt.sh -o <jenkins|agent|PIPELINE_NAME|help>'
  echo "Requires hitt.conf and a working login to the Deployment Engine."
  echo -e "
    \tjenkins \t| Jenkins system log (controller messages).
    \tagent \t\t| jenkins-agent node log (pipeline worker).
    \tPIPELINE_NAME \t| Latest console log for a pipeline job (e.g. helix_onprem_deployment).
    \thelp \t\t| Show this list.
    "
}

showPipelineHelp() { # pipeline mode help
  echo "HITT pipeline mode options - see https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-pipeline-mode.md"
  echo .
  echo 'Usage: bash hitt.sh -k "<command> [options]"'
  echo "Multi-word -k values must be double-quoted (e.g. bash hitt.sh -k \"get lastsuccessful\")."
  echo -e "
    \tget \t\t| Save HELIX_ONPREM_DEPLOYMENT parameter values (defaults, last, lastsuccessful, kickstart, or build number). Optional filename; kickstart output may be edited and used with build.
    \tbuild \t\t| Start a new pipeline run from a settings file created with get.
    \tkickstart \t| Fill parameters from Helix Platform / cluster and start a new run (fresh deployment).
    \tdelete \t\t| Delete build(s) from a pipeline job history. Args: BUILD_NUM or START-END [JOB_NAME] (default: HELIX_ONPREM_DEPLOYMENT).
    \thelp \t\t| Show this list.
    "
  echo "After build or kickstart, rebuild the job in the Deployment Engine and complete any missing values."
  echo "Password parameters in get output are redacted unless -p is used."
  echo "For Deployment Engine logs, use -o (see: bash hitt.sh -o help)."
}

showInfoHelp() { # info mode help
  echo "HITT info mode options - see https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-info-mode.md"
  echo .
  echo 'Usage: bash hitt.sh -m "info <subcommand>"'
  echo "Multi-word -m values must be double-quoted (e.g. bash hitt.sh -m \"info ingress\")."
  echo -e "
    \tcluster \t| Kubernetes/OpenShift version and node resource summary table (allocatable, requested, usage, status).
    \thelix \t\t| Scan the cluster for Helix namespaces (Platform, IS, Deployment Engine, Logging) and show version where available.
    \tingress \t| Ingress controller for Helix INGRESS_CLASS: workload type, namespace, name, and image.
    \tfull \t\t| Full BMC Helix Environment Summary on the console and info.json.
    \thelp \t\t| Show this list.
    "
  echo "Default sub-command when omitted: full"
  echo "Note: info mode is under development; sub-commands and output may change."
}

showOverrideHelp() { # config override options help
  echo "HITT config override options"
  echo .
  echo "Override values from hitt.conf without editing the file:"
  echo -e "
    \t-C VALUE \t| IS_CUSTOMER_SERVICE
    \t-D VALUE \t| CDE_NAMESPACE (Jenkins namespace)
    \t-E VALUE \t| IS_ENVIRONMENT
    \t-H VALUE \t| HP_NAMESPACE
    \t-I VALUE \t| IS_NAMESPACE
    \t-J VALUE \t| JENKINS_URL (full URL)
    \t-P VALUE \t| JENKINS_PASSWORD
    \t-U VALUE \t| JENKINS_USERNAME
    "
  echo "Example: bash hitt.sh -m pre-is -H my-hp-ns -I my-is-ns -C myservice -E prod"
}

showGeneralHelp() {
  echo ""
  echo -e "${BOLD}Helix IS Triage Tool (HITT)${NORMAL}"
  echo -e "${BOLD}Usage: bash $0 -m <post-hp|pre-is|post-is|jenkins>${NORMAL}"
  echo ""
  echo "Examples:"
  echo "bash $0 -m post-hp  - run post HP installation only checks"
  echo "bash $0 -m pre-is   - run pre-installation checks"
  echo "bash $0 -m post-is  - run post-installation checks"
  echo "bash $0 -m jenkins  - run Jenkins configuration checks"
  echo ""
  echo -e "Use ${BOLD}post-hp${NORMAL} after successfully installing the Helix Platform but before using Jenkins."
  echo -e "Use ${BOLD}pre-is${NORMAL} after successfully running the HELIX_GENERATE_CONFIG pipeline but before starting deployment of Helix IS."
  echo -e "Use ${BOLD}post-is${NORMAL} for troubleshooting after IS deployment."
  echo -e "Use ${BOLD}jenkins${NORMAL} to validate Jenkins config - nodes, credentials, libraries etc."
  echo
  echo "Mode-specific help:"
  echo "  bash $0 -h fix         - fix mode options"
  echo "  bash $0 -h info        - info mode options"
  echo "  bash $0 -h utility     - utility mode options"
  echo "  bash $0 -h pipeline    - pipeline mode options"
  echo "  bash $0 -h consolelog  - Deployment Engine log options (-o)"
  echo "  bash $0 -h override    - config override options"
  echo
  echo -e "${BOLD}Interactive help page with HITT use-cases available at https://bit.ly/hitthelp${NORMAL}"
  echo
}

showHittHelp() {
  case "${1}" in
    ""|help|general)
      showGeneralHelp
      ;;
    fix)
      showFixHelp
      ;;
    info)
      showInfoHelp
      ;;
    utility|util)
      showUtilHelp
      ;;
    pipeline)
      showPipelineHelp
      ;;
    consolelog|log)
      showConsoleLogHelp
      ;;
    override)
      showOverrideHelp
      ;;
    *)
      echo -e "${BOLD}ERROR:${NORMAL} Unknown help topic '${1}' (try: fix, info, utility, pipeline, consolelog, override)."
      showGeneralHelp
      exit 1
      ;;
  esac
}

getJenkinsPipelineValues() {
  if [ ${#PIPELINEARGS[@]} -lt 2 ]; then
    logError "999" "Usage: bash $0 -k \"get <defaults|last|lastsuccessful|kickstart|N> [filename]\"" 1
  fi

  local PIPELINE_NAME=HELIX_ONPREM_DEPLOYMENT
  local PIPELINE_BUILD=${PIPELINEARGS[1]}
  local PIPELINE_JSON_FILE="/dev/stdout"
  if [ ${#PIPELINEARGS[@]} -eq 3 ]; then
    PIPELINE_JSON_FILE="${PIPELINEARGS[2]}"
  fi
  JQ_FILTER='.actions[] | select(._class == "hudson.model.ParametersAction") | .parameters[] | "\(.name)=\(.value)"'
  case "${PIPELINE_BUILD}" in
    defaults)
      PIPELINE_VALUES_JSON=$(getPipelineDefaults HELIX_ONPREM_DEPLOYMENT)
      ;;
    kickstart)
      kickstartGatherPlatformContext
      kickstartMergedPipelineJson || exit 1
      PIPELINE_VALUES_JSON="${KICKSTART_MERGED_JSON}"
      ;;
    last)
      PIPELINE_VALUES_JSON=$(getPipelineValuesJSON getLastBuild)
      ;;
    lastsuccessful)
      PIPELINE_VALUES_JSON=$(getPipelineValuesJSON getLastSuccessfulBuild)
      ;;
    [0-9]*)
      PIPELINE_VALUES_JSON=$(getPipelineValuesJSON getBuildByNumber ${PIPELINE_BUILD})
      ;;
    *)
      logError "999" "Usage: bash $0 -k \"get <defaults|last|lastsuccessful|kickstart|N> [filename]\"" 1
      ;;
  esac
  if ! echo "${PIPELINE_VALUES_JSON}" | ${JQ_BIN} -e . &>/dev/null; then
    logError "999" "Pipeline values are not valid JSON." 1
  fi
  local redact_passwords="true"
  if [ "${LOG_PASSWDS}" == "1" ]; then
    redact_passwords="false"
  fi
  echo "${PIPELINE_VALUES_JSON}" | ${JQ_BIN} --argjson redact_passwords "${redact_passwords}" -r 'walk(
    if type == "object" then
      with_entries(
        . as $e
        | if ($e.key | startswith("SEPARATOR")) then empty
          elif ($e.value == "") then empty
          elif $redact_passwords and ($e.key | test("PASSWORD")) then {key: $e.key, value: "***REDACTED***"}
          else $e
          end
      )
    elif type == "array" then
      map(select(. != ""))
    else
      .
    end
  )' > "${PIPELINE_JSON_FILE}"
  if [ "${PIPELINE_JSON_FILE}" != "/dev/stdout" ]; then
    logMessage "Pipeline values saved to '${PIPELINE_JSON_FILE}'"
    if [ "${redact_passwords}" == "true" ]; then
      logMessage "Password parameters were redacted. Use -p to include plain values in the saved file." 1
    fi
  fi
}

triggerHelixOnpremPipelineBuild() {
  # Expects PIPELINE_INPUT_JSON (object). Optional $1 = source label for log messages.
  local source_label="${1:-pipeline values}"
  local job_name="HELIX_ONPREM_DEPLOYMENT"
  local pipeline_defaults_json pipeline_section_params_json pipeline_file_params_json input_version defaults_version http_code override_count
  local jenkins_base rebuild_url rebuild_link pipeline_build_response_file=jenkins-pipeline-build-response.log

  if [ -z "${PIPELINE_INPUT_JSON}" ]; then
    logError "999" "No pipeline parameter JSON supplied." 1
  fi
  if ! echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} . &>/dev/null; then
    logError "999" "Pipeline values JSON is not valid." 1
  fi

  pipeline_file_params_json=$(getPipelineFileParams "${job_name}")
  if ! echo "${pipeline_file_params_json}" | ${JQ_BIN} -e 'type == "array"' &>/dev/null; then
    logError "999" "Unable to discover file parameters from Jenkins job '${job_name}'." 1
  fi
  logMessage "Discovered $(echo "${pipeline_file_params_json}" | ${JQ_BIN} 'length') file parameter(s) to exclude from build request." 1

  pipeline_section_params_json=$(getPipelineSectionParams "${job_name}")
  if ! echo "${pipeline_section_params_json}" | ${JQ_BIN} -e 'type == "array"' &>/dev/null; then
    logError "999" "Unable to discover PIPELINES section parameters from Jenkins job '${job_name}'." 1
  fi
  logMessage "Discovered $(echo "${pipeline_section_params_json}" | ${JQ_BIN} 'length') PIPELINES section parameter(s) from Jenkins." 1

  PIPELINE_INPUT_JSON=$(${JQ_BIN} -c \
    --argjson file_params "${pipeline_file_params_json}" \
    --argjson pipeline_params "${pipeline_section_params_json}" \
    'reduce $file_params[] as $name (.; del(.[$name])) |
    reduce $pipeline_params[] as $name (.;
      if has($name) then . else . + {($name): "false"} end
    )' <<< "${PIPELINE_INPUT_JSON}"
  )

  pipeline_defaults_json=$(getPipelineDefaults "${job_name}")

  input_version=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} -r '.PLATFORM_HELM_VERSION // empty')
  defaults_version=$(echo "${pipeline_defaults_json}" | ${JQ_BIN} -r '.PLATFORM_HELM_VERSION // empty')
  if [ -n "${input_version}" ] && [ "${input_version}" != "${defaults_version}" ]; then
    PIPELINE_INPUT_JSON=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} --arg inputVersion "${input_version}" -c '
      del(.AGENT, .HELM_NODE, .PLATFORM_HELM_VERSION, .SMARTAPPS_HELM_VERSION) |
      . + {
        "SOURCE_VERSION": $inputVersion
        }')
  fi

  if isJenkinsInCluster; then
    PIPELINE_INPUT_JSON=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} -c 'del(.AGENT, .HELM_NODE, .GIT_REPO_DIR, .GIT_USER_HOME_DIR)')
  fi

  PIPELINE_INPUT_JSON=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} --argjson defaults "${pipeline_defaults_json}" -c '
    with_entries(
      select(.key as $k | $defaults | has($k))
    )')

  override_count=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} 'length')
  PIPELINE_INPUT_JSON=$(echo "${PIPELINE_INPUT_JSON}" | ${JQ_BIN} '. | to_entries | map({name: .key, value: .value}) | {parameter: .}')
  logMessage "Building ${job_name} pipeline with ${override_count} parameter override(s) from ${source_label}."
  http_code=$(${CURL_BIN} -X POST --data-urlencode json="${PIPELINE_INPUT_JSON}" -b .cookies -sk -w "%{http_code}" -o "${pipeline_build_response_file}" -H "Jenkins-Crumb:${JENKINS_CRUMB}" "${JENKINS_URL}/job/${job_name}/build" 2>>${HITT_ERR_FILE})
  case "${http_code}" in
    200|201|302)
      rm -f "${pipeline_build_response_file}"
      jenkins_base="${JENKINS_LOG_URL:-${JENKINS_URL}}"
      rebuild_url="${jenkins_base}/job/${job_name}/lastBuild/rebuild/parameterized"
      rebuild_link=$(hittTerminalLink "${rebuild_url}" "HERE")
      logMessage "Pipeline build queued.  Click ${rebuild_link} to rebuild the last job and complete any missing parameter values."
      logMessage "Use ${BOLD}bash hitt.sh -k \"get last\"${NORMAL} to review values."
      ;;
    *)
      logError "999" "Failed to queue ${job_name} pipeline build. See '${pipeline_build_response_file}' for details." 1
      ;;
  esac
}

buildJenkinsPipelineFromFile() {
  if [ ${#PIPELINEARGS[@]} -ne 2 ]; then
    logError "999" "Usage: bash $0 -k \"build json_values_file\"" 1
  fi
  PIPELINE_JSON_FILE="${PIPELINEARGS[1]}"
  if [ ! -f "${PIPELINE_JSON_FILE}" ]; then
    logError "999" "HELIX_ONPREM_DEPLOYMENT pipeline values file '${PIPELINE_JSON_FILE}' not found." 1
  fi
  if ! ${JQ_BIN} . "${PIPELINE_JSON_FILE}" &>/dev/null ; then
    logError "999" "Pipeline values file '${PIPELINE_JSON_FILE}' is not a valid JSON file." 1
  fi
  PIPELINE_INPUT_JSON=$(${JQ_BIN} -c . "${PIPELINE_JSON_FILE}")
  triggerHelixOnpremPipelineBuild "'${PIPELINE_JSON_FILE}'"
}

deleteJenkinsJobs() {
  local PIPELINE_NAME JOBS_RANGE num MSG int1 int2
  JOBS_RANGE="${1}"
  PIPELINE_NAME="${2:-HELIX_ONPREM_DEPLOYMENT}"

  if [[ "${JOBS_RANGE}" =~ ^([0-9]+)$ ]]; then
      num="${BASH_REMATCH[1]}"
      JOBS_RANGE="${num}..${num}"
      MSG="build"
  elif [[ "${JOBS_RANGE}" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      int1="${BASH_REMATCH[1]}"
      int2="${BASH_REMATCH[2]}"
      JOBS_RANGE="${int1}..${int2}"
      MSG="builds"
  else
      logError "999" "Invalid build range. Use a single build number or START-END (for example 42 or 1-50)." 1
  fi

  SCRIPT="
    def job = Jenkins.instance.getItemByFullName('${PIPELINE_NAME}')
    if (job == null) {
        println \"Job not found: ${PIPELINE_NAME}\"
        return
    }
    (${JOBS_RANGE}).each { buildNum ->
    def build = job.getBuildByNumber(buildNum)
    if (build != null) {
        build.delete()
    }
  }"
  logMessage "Deleting ${MSG} ${1} from '${PIPELINE_NAME}'..."
  runJenkinsScript "${SCRIPT}" >/dev/null
  logMessage "Finished deleting ${MSG} ${1} from '${PIPELINE_NAME}' (build numbers that did not exist were skipped)."
}

URLEncode() {
	local dataLength="${#1}"
	local index
	for ((index = 0;index < dataLength;index++)); do
		local char="${1:index:1}"
		case $char in
			[a-zA-Z0-9.~_-])
				printf "$char"
				;;
			*)
				printf "%%%02X" "'$char"
				;;
		esac
	done
}

getUniqueFilename() {
    local filepath="$1"
    # Return immediately if file doesn't exist
    if [[ ! -e "$filepath" ]]; then
        echo "$filepath"
        return 0
    fi
    # Strip extension if present
    local dir base ext
    dir=$(dirname "$filepath")
    base=$(basename "$filepath")
    if [[ "$base" == *.* ]]; then
        ext=".${base##*.}"
        base="${base%.*}"
    else
        ext=""
    fi
    # Find the first available name
    local n=1
    local candidate
    while true; do
        candidate="${dir}/${base}.${n}${ext}"
        [[ ! -e "$candidate" ]] && break
        (( n++ ))
    done
    echo "$candidate"
}

# Populate UTIL_NS_MATCHES with namespaces (IS_NAMESPACE, then HP_NAMESPACE, then CDE_NAMESPACE,
# non-empty and de-duplicated) where kubectl finds the given secret or configmap.
populateUtilK8sObjectMatches() {
  local k8s_kind="$1"
  local object_name="$2"
  local -a distinct_ns=()
  local ns
  local d
  local seen

  UTIL_NS_MATCHES=()
  for ns in "${IS_NAMESPACE}" "${HP_NAMESPACE}" "${CDE_NAMESPACE}"; do
    [[ -z "${ns}" ]] && continue
    seen=0
    for d in "${distinct_ns[@]}"; do
      if [[ "${d}" == "${ns}" ]]; then
        seen=1
        break
      fi
    done
    [[ "${seen}" -eq 1 ]] && continue
    distinct_ns+=("${ns}")
  done
  for ns in "${distinct_ns[@]}"; do
    if ${KUBECTL_BIN} get "${k8s_kind}" "${object_name}" -n "${ns}" &>/dev/null; then
      UTIL_NS_MATCHES+=("${ns}")
    fi
  done
}

exportK8sConfigMap() {
  local CM_NAME="$1"
  local CM_NAMESPACE="$2"
  local CM_JSON
  local export_dir
  local nd
  local nb
  local key

  CM_JSON=$(${KUBECTL_BIN} -n "${CM_NAMESPACE}" get configmap "${CM_NAME}" -o json 2>/dev/null)
  if [[ -z "${CM_JSON}" ]]; then
    logError "999" "ConfigMap '${CM_NAME}' not found in '${CM_NAMESPACE}' namespace." 1
  fi
  if ! echo "${CM_JSON}" | ${JQ_BIN} -e '.metadata.name' &>/dev/null; then
    logError "999" "ConfigMap '${CM_NAME}' not found in '${CM_NAMESPACE}' namespace." 1
  fi
  logMessage "Getting configMap '${CM_NAME}' from '${CM_NAMESPACE}' namespace..."

  nd=$(echo "${CM_JSON}" | ${JQ_BIN} '(.data // {}) | keys | length')
  nb=$(echo "${CM_JSON}" | ${JQ_BIN} '(.binaryData // {}) | keys | length')

  if [[ "${VERBOSITY}" -ge 1 ]]; then
    logMessage "ConfigMap '${CM_NAME}' (${CM_NAMESPACE}): listing keys only (-v); not writing files." 1
    if [[ "${nd}" -eq 0 ]] && [[ "${nb}" -eq 0 ]]; then
      logMessage "  No .data or .binaryData keys." 1
      return 0
    fi
    if [[ "${nd}" -gt 0 ]]; then
      logMessage "  .data keys (${nd}):" 1
      while IFS= read -r key; do
        [[ -z "${key}" ]] && continue
        logMessage "    ${key}" 1
      done < <(echo "${CM_JSON}" | ${JQ_BIN} -r '.data // {} | keys[]' 2>/dev/null)
    fi
    if [[ "${nb}" -gt 0 ]]; then
      logMessage "  .binaryData keys (${nb}):" 1
      while IFS= read -r key; do
        [[ -z "${key}" ]] && continue
        logMessage "    ${key}" 1
      done < <(echo "${CM_JSON}" | ${JQ_BIN} -r '.binaryData // {} | keys[]' 2>/dev/null)
    fi
    return 0
  fi

  export_dir=$(getUniqueFilename "${CM_NAME}")
  mkdir -p "${export_dir}"

  while IFS= read -r key; do
    [[ -z "${key}" ]] && continue
    if [[ "${key}" == */* ]] || [[ "${key}" == *..* ]]; then
      logError "999" "ConfigMap data key '${key}' cannot be used as a file name (contains '/' or '..')." 1
    fi
    echo "${CM_JSON}" | ${JQ_BIN} -r --arg k "${key}" '.data[$k]' > "${export_dir}/${key}"
  done < <(echo "${CM_JSON}" | ${JQ_BIN} -r '.data // {} | keys[]' 2>/dev/null)

  while IFS= read -r key; do
    [[ -z "${key}" ]] && continue
    if [[ "${key}" == */* ]] || [[ "${key}" == *..* ]]; then
      logError "999" "ConfigMap binaryData key '${key}' cannot be used as a file name (contains '/' or '..')." 1
    fi
    echo "${CM_JSON}" | ${JQ_BIN} -r --arg k "${key}" '.binaryData[$k]' | ${BASE64_BIN} -d > "${export_dir}/${key}"
  done < <(echo "${CM_JSON}" | ${JQ_BIN} -r '.binaryData // {} | keys[]' 2>/dev/null)

  if [[ "${nd}" -eq 0 ]] && [[ "${nb}" -eq 0 ]]; then
    logMessage "ConfigMap '${CM_NAME}' has no data or binaryData keys; created directory '${export_dir}'."
  else
    logMessage "ConfigMap '${CM_NAME}' (from ${CM_NAMESPACE}): saved ${nd} data file(s) and ${nb} binary file(s) under '${export_dir}'."
  fi
}

decodeK8sSecret() {
  local SECRETNAME
  local SECRETNAMESPACE
  local K8S_SECRET
  local BINARY_KEYS
  SECRETNAME="${1}"
  SECRETNAMESPACE="${2}"
  K8S_SECRET=$(${KUBECTL_BIN} -n "${SECRETNAMESPACE}" get secret "${SECRETNAME}" -o json 2>/dev/null)
  # Check secret was found
  if [[ -z "${K8S_SECRET}" ]]; then
    logError "999" "Secret '${SECRETNAME}' not found in '${SECRETNAMESPACE}' namespace." 1
  fi
  # Test that it contains data we can decode
  if ! echo "${K8S_SECRET}" | ${JQ_BIN} -e '.data | type == "object" and length > 0' >/dev/null 2>&1; then
    logError "999" "Secret '${SECRETNAME}' does not contain data that can be decoded by HITT." 1
  fi
  logMessage "Getting secret '${SECRETNAME}' from '${SECRETNAMESPACE}' namespace..."
  # Check for binary data and decode
  BINARY_KEYS=($(echo "${K8S_SECRET}" | ${JQ_BIN} -r '
  .data | to_entries[] |
  select(
    (.value | @base64d | test("[^\\x09\\x0A\\x0D\\x20-\\x7E]"))
  ) | .key
  '))
  if [ -n "${BINARY_KEYS[*]}" ]; then
    logMessage "Binary data found - saving keys as files."
    for k in "${BINARY_KEYS[@]}"; do
      local fname
      fname=$(getUniqueFilename "${k}")
      logMessage "Saving data from key '${k}' in secret '${SECRETNAME}' as file named '${fname}'"
      echo "${K8S_SECRET}" | ${JQ_BIN} -r --arg key "${k}" '.data[$key]' | ${BASE64_BIN} -d > "${fname}"
      # Remove key from JSON
      K8S_SECRET=$(echo "${K8S_SECRET}" | ${JQ_BIN} --arg key "$k" 'del(.data[$key])')
    done
  fi
  # Decode remainder
  echo "${K8S_SECRET}" | ${JQ_BIN} -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'
}

parseUtilGet() {
  case "${UTILARGS[1]}" in
    arlicense)
      initISAdminREST
      IS_LIC=$(getISServerInfo licensetype)
      IS_LIC_FIXED=$(getISServerInfo fixedlicensecount)
      IS_LIC_FLOATING=$(getISServerInfo floatinglicensecount)
      logMessage "IS license type is '${IS_LIC}' (${IS_LIC_FIXED} fixed / ${IS_LIC_FLOATING} floating)."
      ;;
    jwt)
      getISJWTToken "${UTILARGS[2]}" "${UTILARGS[3]}"
      ;;
    dbid)
      getISDbID
      ;;
    secret)
      if [ ${#UTILARGS[@]} -lt 3 ] || [ ${#UTILARGS[@]} -gt 4 ]; then
        logError "999" "Usage: bash $0 -u \"get secret SECRETNAME [NAMESPACE]\"" 1
      fi
      if [ ${#UTILARGS[@]} -eq 4 ]; then
        decodeK8sSecret "${UTILARGS[2]}" "${UTILARGS[3]}"
      else
        populateUtilK8sObjectMatches secret "${UTILARGS[2]}"
        case ${#UTIL_NS_MATCHES[@]} in
          0)
            logError "999" "Secret '${UTILARGS[2]}' not found in IS_NAMESPACE, HP_NAMESPACE, or CDE_NAMESPACE from hitt.conf. Pass NAMESPACE explicitly, e.g. bash $0 -u \"get secret ${UTILARGS[2]} NAMESPACE\"." 1
            ;;
          1)
            decodeK8sSecret "${UTILARGS[2]}" "${UTIL_NS_MATCHES[0]}"
            ;;
          *)
            if [[ "${QUIET}" == "1" ]]; then
              logError "999" "Secret '${UTILARGS[2]}' exists in more than one configured namespace; omit -q to choose interactively, or pass NAMESPACE explicitly." 1
            fi
            logStatus "Secret '${UTILARGS[2]}' exists in multiple namespaces — select namespace:" 1
            decodeK8sSecret "${UTILARGS[2]}" "$(selectFromArray UTIL_NS_MATCHES)"
            ;;
        esac
      fi
      ;;
    configmap)
      if [ ${#UTILARGS[@]} -lt 3 ] || [ ${#UTILARGS[@]} -gt 4 ]; then
        logError "999" "Usage: bash $0 -u \"get configmap CM_NAME [NAMESPACE]\"" 1
      fi
      if [ ${#UTILARGS[@]} -eq 4 ]; then
        exportK8sConfigMap "${UTILARGS[2]}" "${UTILARGS[3]}"
      else
        populateUtilK8sObjectMatches configmap "${UTILARGS[2]}"
        case ${#UTIL_NS_MATCHES[@]} in
          0)
            logError "999" "ConfigMap '${UTILARGS[2]}' not found in IS_NAMESPACE, HP_NAMESPACE, or CDE_NAMESPACE from hitt.conf. Pass NAMESPACE explicitly, e.g. bash $0 -u \"get configmap ${UTILARGS[2]} NAMESPACE\"." 1
            ;;
          1)
            exportK8sConfigMap "${UTILARGS[2]}" "${UTIL_NS_MATCHES[0]}"
            ;;
          *)
            if [[ "${QUIET}" == "1" ]]; then
              logError "999" "ConfigMap '${UTILARGS[2]}' exists in more than one configured namespace; omit -q to choose interactively, or pass NAMESPACE explicitly." 1
            fi
            logStatus "ConfigMap '${UTILARGS[2]}' exists in multiple namespaces — select namespace:" 1
            exportK8sConfigMap "${UTILARGS[2]}" "$(selectFromArray UTIL_NS_MATCHES)"
            ;;
        esac
      fi
      ;;
    forms)
      if [ ${#UTILARGS[@]} -le 2 ] ; then
        logError "999" "Usage: bash $0 -u \"get forms KEYWORD\"" 1
      fi
      KEYWORD="${UTILARGS[2]}"
      if ((${#UTILARGS[@]} > 3)); then
        KEYWORD="${UTILARGS[*]:2}"   # or "${UTILARGS[@]:2}" with IFS=' '
      fi
      initISAdminREST
      JSON=$(runARRESTSQL "select [name],[Schema ID],[schemaType],[nextId],[overlayProp] from [AR System Metadata: arschema] where [name] like '%${KEYWORD}%'")
      NUM_ROWS=$(echo "${JSON}" | ${JQ_BIN} '.rows | length')
      if [[ -z "${NUM_ROWS}" ]] || [[ "${NUM_ROWS}" == "null" ]]; then
        logError "999" "AR SQL query response did not include a row count." 1
      fi
      if [[ "${NUM_ROWS}" -eq 0 ]]; then
        logError "999" "No forms with '${KEYWORD}' in their name found." 1
      fi
      STATUS_MSG="Found ${NUM_ROWS} forms with names containing '${KEYWORD}':"
      if [[ "${NUM_ROWS}" -gt 100 ]]; then
        # check for an exact match
        local EXACT_ROWS
        JSON=$(runARRESTSQL "select [name],[Schema ID],[schemaType],[nextId],[overlayProp] from [AR System Metadata: arschema] where [name] = '${KEYWORD}'")
        EXACT_ROWS=$(echo "${JSON}" | ${JQ_BIN} '.rows | length')
        if [[ "${EXACT_ROWS}" -eq 1 ]]; then
          STATUS_MSG="Found ${NUM_ROWS} forms with names containing '${KEYWORD}' including one exact match. Please use a more specific keyword to see others."
        else
          logError "999" "${NUM_ROWS} forms found with '${KEYWORD}' in their name - please use a more specific keyword." 1
        fi
      fi
      logStatus "${STATUS_MSG}"
      echo "${JSON}" | ${JQ_BIN} -r '
        ([.columns[].label] | map("\u001b[1m" + . + "\u001b[0m")),
        (.rows[]
          | .[2] |= (
              if . == 1 then "regular"
              elif . == 2 then "join"
              elif . == 3 then "view"
              elif . == 4 then "display-only"
              elif . == 5 then "vendor"
              elif . == 6 then "placeholder"
              else "unknown" end
            )
          | .[4] |= (
              if . == 0 then "unmodified"
              elif . == 1 then "overlaid"
              elif . == 2 then "overlay"
              elif . == 4 then "custom"
              else "unknown" end
            )
        )
        | @tsv
      ' | column -t -s $'\t'
      exit
      echo "${JSON}" | ${JQ_BIN} -r '
        "\u001b[1mForm Name\tSchema ID\u001b[0m",
        (.rows[] | [.[]] | @tsv)
      ' | column -t -s $'\t'
      ;;
    fields)
      if [ ${#UTILARGS[@]} -lt 3 ] ; then
        logError "999" "Usage: bash $0 -u \"get fields SCHEMAID [KEYWORD]\"" 1
      fi
      SCHEMAID=${UTILARGS[2]}
      if [[ ! ${SCHEMAID} =~ ^[0-9]+$ ]]; then
        logError "999" "Invalid schemaId '${SCHEMAID}' - must be a number. Use \"get forms\" to find schemaId." 1
      fi
      KEYWORD="${UTILARGS[3]}"
      if ((${#UTILARGS[@]} > 4)); then
        KEYWORD="${UTILARGS[*]:3}"
      fi
      initISAdminREST
      if [ -z "${KEYWORD}" ]; then
        JSON=$(runARRESTSQL "select [fieldName],[fieldId] from [AR System Metadata: field] where [schemaId] = '${SCHEMAID}'")
        ERR_MSG="No fields found for form with schemaId ${SCHEMAID}."
      else
        JSON=$(runARRESTSQL "select [fieldName],[fieldId] from [AR System Metadata: field] where [schemaId] = '${SCHEMAID}' and [fieldName] like '%${KEYWORD}%'")
        ERR_MSG="No fields found with '${KEYWORD}' in their name for schemaId ${SCHEMAID}."
      fi
      NUM_ROWS=$(echo "${JSON}" | ${JQ_BIN} '.rows | length')
      if [[ -z "${NUM_ROWS}" ]] || [[ "${NUM_ROWS}" == "null" ]]; then
        logError "999" "AR SQL query response did not include a row count." 1
      fi
      if [[ "${NUM_ROWS}" -eq 0 ]]; then
        logError "999" "${ERR_MSG}" 1
      fi
      if [[ "${NUM_ROWS}" -gt 100 ]]; then
        logError "999" "${NUM_ROWS} fields found - please add a keyword." 1
      fi
      logStatus "Found ${NUM_ROWS} fields:"
      echo "${JSON}" | ${JQ_BIN} -r '
        "\u001b[1mField Name\tField ID\u001b[0m",
        (.rows[] | [.[]] | @tsv)
      ' | column -t -s $'\t'

      ;;
    *)
     logError "999" "'${UTILARGS[1]}' is not a valid utility mode get command option."
     ;;
  esac
}

initISAdminREST() {
  checkToolVersion kubectl
  getVersions
  getDomain
  buildISAliasesArray
  getISAdminCreds
  if ! getISJWT; then
    logError "999" "Failed to authenticate — cannot run query." 1
  fi
}

genTctlConfig() {
  local TMS_USER
  local TMS_PASSWD
  local TMS_URL
  local APPURL
  local CLIENTSECRET
  local CLIENTID
  local RSSOURL
  logMessage "Getting data from TMS..."
  # If tms-realm-admin secret exists (v23 onwards) we should use it otherwise use the tms-superuser-job
  if ${KUBECTL_BIN} get secret -n "${HP_NAMESPACE}" tms-realm-admin &>/dev/null; then
    TMS_USER=$(${KUBECTL_BIN} get secret -n "${HP_NAMESPACE}" tms-realm-admin -o jsonpath='{.data.local_username}' | ${BASE64_BIN} -d)
    TMS_PASSWD=$(${KUBECTL_BIN} get secret -n "${HP_NAMESPACE}" tms-realm-admin -o jsonpath='{.data.local_password}' | ${BASE64_BIN} -d)
  else
    TMS_USER=$(${KUBECTL_BIN} get job -n "${HP_NAMESPACE}" tms-superuser-job -o=jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="LOCAL_USER_NAME")].value}')
    TMS_PASSWD=$(${KUBECTL_BIN} get job -n "${HP_NAMESPACE}" tms-superuser-job -o=jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="LOCAL_USER_PASSWORD")].value}')
  fi

  # Get the config file values
  TMS_URL=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get deployment tms -o=jsonpath='{.spec.template.spec.containers[?(@.name=="tms")].env[?(@.name=="ADE_PLATFORM_BASE_URL")].value}')
  APPURL="${TMS_URL%/*}"
  CLIENTSECRET=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret tms-auth-proxy-secret -o jsonpath='{.data.clientsecret}' | ${BASE64_BIN} -d -w 0)
  CLIENTID=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret tms-auth-proxy-secret -o jsonpath='{.data.clientid}' | ${BASE64_BIN} -d -w 0)
  RSSOURL=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get cm rsso-admin-tas -o jsonpath='{.data.rssourl}{"/rsso\n"}')

  echo
  echo -e "RSSO credentials are ${TMS_USER}/${TMS_PASSWD}" >/dev/tty
  echo "
  appurl: ${APPURL}
  clientid: ${CLIENTID}
  clientsecret: ${CLIENTSECRET}
  enableauth: true
  rssourl: ${RSSOURL}
  "
}

runARRESTSQL() {
  # POST api/arsys/v1.0/sql/query; prints JSON on success or logError+exit
  local SQL="$1"
  local RESP_FILE
  local HTTP_CODE
  local AR_DETAIL

  RESP_FILE=$(mktemp)
  HTTP_CODE=$(${JQ_BIN} -n --arg sql "${SQL}" '{sql: $sql}' | \
    ${CURL_BIN} -sk -w "%{http_code}" -o "${RESP_FILE}" -X POST \
      "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/arsys/v1.0/sql/query" \
      -H "Authorization: AR-JWT ${ARJWT}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -d @-)
  if [[ "${HTTP_CODE}" -lt 200 ]] || [[ "${HTTP_CODE}" -ge 300 ]]; then
    AR_DETAIL=$(head -c 300 "${RESP_FILE}" 2>/dev/null | tr '\n' ' ')
    rm -f "${RESP_FILE}"
    logError "999" "AR SQL query failed (HTTP ${HTTP_CODE}).${AR_DETAIL:+ ${AR_DETAIL}}" 1
  fi
  if [[ ! -s "${RESP_FILE}" ]]; then
    rm -f "${RESP_FILE}"
    logError "999" "AR SQL query returned an empty response." 1
  fi
  if ! ${JQ_BIN} -e . "${RESP_FILE}" &>/dev/null; then
    AR_DETAIL=$(head -c 300 "${RESP_FILE}" 2>/dev/null | tr '\n' ' ')
    rm -f "${RESP_FILE}"
    logError "999" "AR SQL query did not return valid JSON.${AR_DETAIL:+ ${AR_DETAIL}}" 1
  fi
  if ! ${JQ_BIN} -e '(.rows | type) == "array"' "${RESP_FILE}" &>/dev/null; then
    AR_DETAIL=$(${JQ_BIN} -r '
      [.message, .error, .errorMessage, .statusReason, .status] |
      map(select(. != null and (. | tostring) != "")) | first // empty
    ' "${RESP_FILE}" 2>/dev/null)
    [[ -z "${AR_DETAIL}" ]] && AR_DETAIL=$(head -c 300 "${RESP_FILE}" 2>/dev/null | tr '\n' ' ')
    rm -f "${RESP_FILE}"
    logError "999" "AR SQL query returned an unexpected response (no rows array).${AR_DETAIL:+ ${AR_DETAIL}}" 1
  fi
  cat "${RESP_FILE}"
  rm -f "${RESP_FILE}"
}

parseUtilSQL() {
  if [ ${#UTILARGS[@]} -eq 1 ]; then
    logError "999" "Usage: bash $0 -u \"sql AR_SQL_QUERY\"" 1
  fi
  initISAdminREST
  runARRESTSQL "${UTILARGS[*]:1}"
}

# getK8sNodeDetails  — fills global K8S_NODE_DETAILS_TABLE (pipe rows, \\n-separated);
#                      and K8S_OOM_PODS_TABLE (POD_NAME|CONTAINER_NAME|NAMESPACE|NODE_NAME rows);
#                      returns 0 on success, 1 on failure (does not exit).
# printK8sNodeDetails — formats K8S_NODE_DETAILS_TABLE to stdout; returns 1 if empty.
# printK8sOomPods     — formats K8S_OOM_PODS_TABLE to stdout; returns 1 if no OOM pods.
# =============================================================================
getK8sNodeDetails() {
  local nodes_json top_nodes_text node_name node_type runtime alloc_cpu alloc_mem allocatable
  local node_top pct_cpu pct_mem actual_usage conditions is_ready node_status pods_json
  local req_cpu req_cpu_milli req_mem req_mem_mi allocated count_running count_bad count_crash
  local pod_stats count_oom TABLE_DATA OOM_PODS_DATA oom_row node

  K8S_NODE_DETAILS_TABLE=""
  K8S_NODE_DETAILS_JSON=""
  K8S_OOM_PODS_TABLE=""

  nodes_json=$(${KUBECTL_BIN} get nodes -o json 2>>"${HITT_ERR_FILE}") || true
  if [[ -z "${nodes_json}" ]] || ! echo "${nodes_json}" | ${JQ_BIN} -e . >/dev/null 2>>"${HITT_ERR_FILE}"; then
    # Do not pass exit flag to logError — caller may continue; check return value.
    logError "265" "Unable to read Kubernetes nodes as JSON - check kubeconfig, cluster reachability, and '${KUBECTL_BIN}'."
    return 1
  fi

  # Text-only top (no -o); older kubectl rejects "top nodes -o json".
  top_nodes_text=$(${KUBECTL_BIN} top nodes --no-headers 2>>"${HITT_ERR_FILE}") || top_nodes_text=""
  if [[ -z "${top_nodes_text}" ]] && [[ "${VERBOSITY}" -ge 1 ]] && [[ "${QUIET}" == "0" ]]; then
    logMessage "Could not read 'kubectl top nodes' snapshot; will try per-node top or show Metrics N/A." 1
  fi

  TABLE_DATA=""
  OOM_PODS_DATA=""
  # Use $'\n' — in bash, "\n" inside "..." is a literal backslash+n, not a newline (echo -e expands it for display; jq does not).
  TABLE_DATA+=$'NODE_NAME|NODE_TYPE|ALLOCATABLE_(CPU/MEM)|ALLOCATED_REQ_(CPU/MEM)|ACTUAL_USAGE|NODE_STATUS/CONDITIONS|PODS_(RUN/BAD/CRASH)|OOM_KILLS|CONTAINER_RUNTIME\n'
  OOM_PODS_DATA+=$'POD_NAME|CONTAINER_NAME|NAMESPACE|NODE_NAME\n'

  while read -r node; do
    [[ -z "${node}" ]] && continue

    node_name=$(echo "${node}" | ${JQ_BIN} -r '.metadata.name')
    node_type=$(echo "${node}" | ${JQ_BIN} -r '[.metadata.labels | to_entries[] | select(.key | startswith("node-role.kubernetes.io/")) | .key | split("/")[1]] | join(",")')
    [[ -z "${node_type}" ]] && node_type="worker"

    runtime=$(echo "${node}" | ${JQ_BIN} -r '.status.nodeInfo.containerRuntimeVersion')

    alloc_cpu=$(echo "${node}" | ${JQ_BIN} -r '.status.allocatable.cpu')
    alloc_mem=$(echo "${node}" | ${JQ_BIN} -r '
      .status.allocatable.memory
      | if endswith("Gi") then (sub("Gi$"; "") | tonumber * 1024)
        elif endswith("G") then (sub("G$"; "") | tonumber * 953)
        elif endswith("Mi") then (sub("Mi$"; "") | tonumber)
        elif endswith("M") then (sub("M$"; "") | tonumber * 0.953)
        elif endswith("Ki") then (sub("Ki$"; "") | tonumber / 1024)
        else (tonumber / 1024 / 1024)
        end
      | round
      | tostring + "Mi"
    ' 2>>"${HITT_ERR_FILE}")
    alloc_mem="${alloc_mem:-0Mi}"
    allocatable="${alloc_cpu}_/_${alloc_mem}"

    node_top=""
    if [[ -n "${top_nodes_text}" ]]; then
      node_top=$(printf '%s\n' "${top_nodes_text}" | awk -v n="${node_name}" '{ gsub(/\r/, ""); if ($1 == n) { print; exit } }')
    fi
    if [[ -z "${node_top}" ]]; then
      node_top=$(${KUBECTL_BIN} top node "${node_name}" --no-headers 2>>"${HITT_ERR_FILE}") || node_top=""
    fi
    # Typical: NAME  CPU(cores)  CPU%  MEMORY(bytes)  MEMORY%  → % columns $3 and $5
    if [[ -n "${node_top}" ]]; then
      pct_cpu=$(echo "${node_top}" | awk '{ gsub(/\r/, ""); print $3 }')
      pct_mem=$(echo "${node_top}" | awk '{ gsub(/\r/, ""); print $5 }')
      [[ -z "${pct_cpu}" ]] && pct_cpu="0%"
      [[ -z "${pct_mem}" ]] && pct_mem="0%"
      actual_usage="${pct_cpu}_/_${pct_mem}"
    else
      actual_usage="Metrics_N/A"
    fi

    conditions=$(echo "${node}" | ${JQ_BIN} -r '.status.conditions[] | select(.status == "True" and .type != "Ready") | .type' | tr '\n' ',' | sed 's/,$//')
    is_ready=$(echo "${node}" | ${JQ_BIN} -r '.status.conditions[] | select(.type == "Ready") | .status')

    if [[ "${is_ready}" != "True" ]]; then
      node_status="NotReady"
    elif [[ -z "${conditions}" ]]; then
      node_status="Healthy"
    else
      node_status="Pressure:${conditions}"
    fi

    pods_json=$(${KUBECTL_BIN} get pods --all-namespaces --field-selector "spec.nodeName=${node_name}" -o json 2>>"${HITT_ERR_FILE}") || pods_json='{"items":[]}'

    req_cpu=$(echo "${pods_json}" | ${JQ_BIN} -r '[.items[].spec.containers[].resources.requests.cpu // "0"] | map(if endswith("m") then (sub("m$"; "") | tonumber) else (tonumber * 1000) end) | add' 2>>"${HITT_ERR_FILE}")
    req_cpu_milli="${req_cpu:-0}m"

    req_mem=$(echo "${pods_json}" | ${JQ_BIN} -r '[.items[].spec.containers[].resources.requests.memory // "0"] | map(if endswith("Gi") then (sub("Gi$"; "") | tonumber * 1024) elif endswith("G") then (sub("G$"; "") | tonumber * 953) elif endswith("Mi") then (sub("Mi$"; "") | tonumber) elif endswith("M") then (sub("M$"; "") | tonumber * 0.953) elif endswith("Ki") then (sub("Ki$"; "") | tonumber / 1024) else (tonumber / 1024 / 1024) end) | add | round' 2>>"${HITT_ERR_FILE}")
    req_mem_mi="${req_mem:-0}Mi"

    allocated="${req_cpu_milli}_/_${req_mem_mi}"

    count_running=$(echo "${pods_json}" | ${JQ_BIN} '[.items[] | select(.status.phase == "Running")] | length')
    count_bad=$(echo "${pods_json}" | ${JQ_BIN} '[.items[] | select(.status.phase as $p | ["Failed", "Unknown"] | any(. == $p))] | length')
    count_crash=$(echo "${pods_json}" | ${JQ_BIN} '[.items[].status.containerStatuses // [] | .[] | select(.state.waiting.reason == "CrashLoopBackOff")] | length')
    pod_stats="${count_running}/${count_bad}/${count_crash}"

    count_oom=$(echo "${pods_json}" | ${JQ_BIN} '[.items[].status.containerStatuses // [] | .[] | select(.lastState.terminated.reason == "OOMKilled")] | length')

    while IFS= read -r oom_row; do
      [[ -z "${oom_row}" ]] && continue
      OOM_PODS_DATA+="${oom_row}"$'\n'
    done < <(echo "${pods_json}" | ${JQ_BIN} -r '
      [.items[]
       | . as $pod
       | (.status.containerStatuses // [])
       | .[]
       | select(.lastState.terminated.reason == "OOMKilled")
       | "\($pod.metadata.name)|\(.name)|\($pod.metadata.namespace)|\($pod.spec.nodeName)"
      ] | .[]
    ' 2>>"${HITT_ERR_FILE}")

    TABLE_DATA+="${node_name}|${node_type}|${allocatable}|${allocated}|${actual_usage}|${node_status}|${pod_stats}|${count_oom}|${runtime}"$'\n'
  done < <(echo "${nodes_json}" | ${JQ_BIN} -c '.items[]')

  K8S_NODE_DETAILS_TABLE="${TABLE_DATA}"
  K8S_OOM_PODS_TABLE="${OOM_PODS_DATA}"
  K8S_NODE_DETAILS_JSON=$(
    printf '%s' "${TABLE_DATA}" | ${JQ_BIN} -Rs '
      split("\n")
      | map(select(length > 0 and contains("|")))
      | if length < 2 then []
        else
          (.[0] | split("|") | map(gsub("^[[:space:]]+|[[:space:]]+$"; ""))) as $keys
          | .[1:]
          | map(
              split("|") as $vals
              | ($keys | length) as $n
              | [range(0; $n) | . as $i | {($keys[$i]): (($vals[$i] // "") | gsub("^[[:space:]]+|[[:space:]]+$"; ""))}] | add
            )
        end
    ' 2>>"${HITT_ERR_FILE}" | hittJsonApplyInfoKeyNormalization 2>>"${HITT_ERR_FILE}"
  ) || K8S_NODE_DETAILS_JSON='[]'
  return 0
}

printK8sNodeDetails() {
  if [[ -z "${K8S_NODE_DETAILS_TABLE}" ]]; then
    echo "Not available. Check kubeconfig, cluster reachability and permissions."
    return 1
  fi
  echo -e "${K8S_NODE_DETAILS_TABLE}" | column -s '|' -t | sed 's/_/ /g'
  return 0
}

printK8sOomPods() {
  if [[ -z "${K8S_OOM_PODS_TABLE}" ]] || [[ $(printf '%s' "${K8S_OOM_PODS_TABLE}" | awk 'NF' | wc -l) -lt 2 ]]; then
    return 1
  fi
  echo -e "${K8S_OOM_PODS_TABLE}" | column -s '|' -t  | sed 's/_/ /g'
  return 0
}

# =============================================================================
# Ingress controller discovery
# discoverIngressControllerDetails [INGRESS_CLASS_NAME]
#   Resolves the controller workload for that IngressClass (cluster-wide deploy/ds list).
#   Class name: first arg, else INGRESS_CLASS_NAME, else HP_INGRESS_CLASS (Helix config mirror), else "nginx".
# Workloads are listed cluster-wide (-A); controller is not assumed to live in the app/Helix namespace.
# Matching: score Deployments/DaemonSets cluster-wide; prefer ingress/nginx image/name, args, and
#           annotations over INGRESS_CLASS env alone (avoids false positives from app workloads).
# Sets globals: INGRESS_CLASS_NAME, INGRESS_CLASS_SPEC_CONTROLLER, INGRESS_CONTROLLER_TYPE (deployment|daemonset|unknown),
#               INGRESS_CONTROLLER_NAMESPACE, INGRESS_CONTROLLER_NAME, INGRESS_CONTROLLER_IMAGE
# =============================================================================
discoverIngressControllerDetails() {
  local ic_json controller workload_json match_json ic_name

  ic_name="${1:-}"
  [[ -z "${ic_name}" ]] && ic_name="nginx"
  INGRESS_CLASS_NAME="${ic_name}"

  INGRESS_CLASS_SPEC_CONTROLLER=""
  INGRESS_CONTROLLER_TYPE="unknown"
  INGRESS_CONTROLLER_NAMESPACE=""
  INGRESS_CONTROLLER_NAME=""
  INGRESS_CONTROLLER_IMAGE=""

  ic_json=$(${KUBECTL_BIN} get "ingressclass/${INGRESS_CLASS_NAME}" -o json 2>>"${HITT_ERR_FILE}") || ic_json=""
  if [[ -z "${ic_json}" ]] || ! echo "${ic_json}" | ${JQ_BIN} -e . >/dev/null 2>>"${HITT_ERR_FILE}"; then
    logError "266" "IngressClass '${INGRESS_CLASS_NAME}' not found or not readable as JSON."
    return 1
  fi

  controller=$(echo "${ic_json}" | ${JQ_BIN} -r '.spec.controller // ""')
  INGRESS_CLASS_SPEC_CONTROLLER="${controller}"

  workload_json=$(${KUBECTL_BIN} get deploy,daemonset -A -o json 2>>"${HITT_ERR_FILE}") || workload_json=""
  if [[ -z "${workload_json}" ]] || ! echo "${workload_json}" | ${JQ_BIN} -e '.items' >/dev/null 2>>"${HITT_ERR_FILE}"; then
    logError "267" "Unable to list Deployments and DaemonSets for ingress controller discovery."
    return 1
  fi

  match_json=$(echo "${workload_json}" | ${JQ_BIN} -c --arg ic "${INGRESS_CLASS_NAME}" --arg ctrl "${controller}" '
    def args_text($c): (($c.args // []) | join(" "));
    def container_has_ingress_args($c):
      (args_text($c) | test("--ingress-class=" + $ic + "( |$)"))
      or (args_text($c) | test("--class=" + $ic + "( |$)"))
      or (($ctrl | length) > 0 and (args_text($c) | index($ctrl)) != null);
    def workload_score($w):
      (if ($w.metadata.name | test("ingress"; "i")) then 100 else 0 end)
      + (if ($w.metadata.name | test("nginx|traefik|haproxy"; "i")) then 80 else 0 end)
      + (if ($w.spec.template.metadata.annotations["kubernetes.io/ingress.class"]? // "") == $ic then 90 else 0 end)
      + (if any($w.spec.template.spec.containers[]?; container_has_ingress_args(.)) then 85 else 0 end)
      + (if any($w.spec.template.spec.containers[]?; .image | test("ingress-nginx|nginx-ingress|traefik|haproxy|ingress-controller"; "i")) then 75 else 0 end)
      + (if any($w.spec.template.spec.containers[]? | (.env // [])[]?;
            (.name == "INGRESS_CLASS" or .name == "INGRESS_CLASS_NAME") and .value == $ic
          ) then 15 else 0 end)
      - (if ($w.metadata.name | test("smart-graph|midtier|platform-fts|rsso|elastic|kafka|zookeeper"; "i")) then 80 else 0 end)
      - (if any($w.spec.template.spec.containers[]?; .image | test("smart-graph|midtier-user|platform-fts"; "i")) then 100 else 0 end);
    [.items[] | select(.kind == "Deployment" or .kind == "DaemonSet")
     | { score: workload_score(.), item: . }
     | select(.score > 0)
    ] | sort_by(-.score) | .[0].item // empty
  ')

  if [[ -z "${match_json}" || "${match_json}" == "null" ]]; then
    [[ "${VERBOSITY}" -ge 1 ]] && [[ "${QUIET}" == "0" ]] && logMessage "No Deployment/DaemonSet matched IngressClass '${INGRESS_CLASS_NAME}' or controller '${controller}' (args, env, or pod template annotation)." 1
    return 1
  fi

  INGRESS_CONTROLLER_NAMESPACE=$(echo "${match_json}" | ${JQ_BIN} -r '.metadata.namespace // ""')
  INGRESS_CONTROLLER_NAME=$(echo "${match_json}" | ${JQ_BIN} -r '.metadata.name // ""')

  case $(echo "${match_json}" | ${JQ_BIN} -r '.kind // ""') in
    Deployment) INGRESS_CONTROLLER_TYPE="deployment" ;;
    DaemonSet) INGRESS_CONTROLLER_TYPE="daemonset" ;;
    *) INGRESS_CONTROLLER_TYPE="unknown" ;;
  esac

  INGRESS_CONTROLLER_IMAGE=$(echo "${match_json}" | ${JQ_BIN} -r --arg ic "${INGRESS_CLASS_NAME}" --arg ctrl "${controller}" '
    def args_text($c): (($c.args // []) | join(" "));
    def container_score($c):
      (if ($c.name | test("controller"; "i")) then 50 else 0 end)
      + (if ($c.image | test("ingress-nginx|nginx-ingress|traefik|haproxy|ingress-controller"; "i")) then 90 else 0 end)
      + (if (args_text($c) | test("--ingress-class=" + $ic + "( |$)")) then 70 else 0 end)
      + (if (args_text($c) | test("--class=" + $ic + "( |$)")) then 65 else 0 end)
      + (if (($ctrl | length) > 0) and (args_text($c) | index($ctrl)) != null then 60 else 0 end)
      + (if any(($c.env // [])[]?; (.name == "INGRESS_CLASS" or .name == "INGRESS_CLASS_NAME") and .value == $ic) then 10 else 0 end)
      - (if ($c.image | test("smart-graph|midtier|sidecar|exporter"; "i")) then 120 else 0 end);
    ([.spec.template.spec.containers[]?
      | { score: container_score(.), image: (.image // "") }
      | select(.image != "")
    ] | sort_by(-.score) | .[0].image) // (.spec.template.spec.containers[0].image // "")
  ')

  return 0
}

# Human-readable info summary only (-m info): section headers, aligned labels, tctl tables via column.
hittInfoPrintSection() {
  echo ""
  echo "--------------------------------------------------------------------------------"
  echo -e "${BOLD}${1}${NORMAL}"
}

hittInfoPrintKv() {
  printf '%-32s %s\n' "${1}:" "${2}"
}

# Pretty-print tctl tables for the terminal. Prefer pipe-separated columns (-s '|') so
# service names with internal spaces are not split; fall back to whitespace columns otherwise.
hittFormatTctlTableForDisplay() {
  local raw="${1:-}"
  [[ -z "${raw//[[:space:]]/}" ]] && return 0
  if [[ "${raw}" == *'|'* ]]; then
    printf '%s\n' "${raw}" | column -s '|' -t 2>/dev/null || printf '%s\n' "${raw}"
  else
    printf '%s\n' "${raw}" | column -t 2>/dev/null || printf '%s\n' "${raw}"
  fi
}

# printIngressControllerDetails — aligned lines for info summary (see hittInfoPrintKv).
printIngressControllerDetails() {
  hittInfoPrintKv "Ingress class (Helix config)" "${HP_INGRESS_CLASS}"
  hittInfoPrintKv "Workload type" "${INGRESS_CONTROLLER_TYPE:-unknown}"
  hittInfoPrintKv "Namespace" "${INGRESS_CONTROLLER_NAMESPACE:-unknown}"
  hittInfoPrintKv "Workload" "${INGRESS_CONTROLLER_NAME:-unknown}"
  hittInfoPrintKv "Image" "${INGRESS_CONTROLLER_IMAGE:-unknown}"
}

gatherInfo() {
  # Main function to collect data for info mode
  ENV_ARRAY=("Dev" "QA" "Pre-prod" "Prod" "Other")
  echo ""
  echo "Please select your environment type:"
  ENV_TYPE=$(selectFromArray ENV_ARRAY)
  if [ "${ENV_TYPE}" == "Other" ]; then
    while [[ -z "${ENV_OTHER}" ]]; do read -p "Please enter your environment type : " ENV_OTHER; done
    ENV_TYPE="${ENV_OTHER}"
  fi
  echo ""
  if askYesNo "Is the system live?" ; then
    ENV_LIVE=true
  else
    ENV_LIVE=false
  fi

  QUIET=1
  HP_TENANTS_JSON=''
  HP_SERVICES_JSON=''
  logStatus "Gathering cluster information..." 1
  checkToolVersion kubectl
  getK8sNodeDetails
  getVersions
  logStatus "Gathering Helix Platform information..." 1
  setVarsFromPlatform
  if checkK8sAuth get ingressclasses; then
    INGRESS_CLASSES=$(${KUBECTL_BIN} get ingressclasses)
    discoverIngressControllerDetails "${HP_INGRESS_CLASS}"
  fi
  checkHelixLoggingDeployed
  checkHPRegistryDetails
  getRSSODetails
  getDomain
  getTenantDetails
  if [ "${HP_SM_PLATFORM_CORE}" == "no" ]; then
    deleteTCTLJob
    deployTCTL "get tenant"
    getTCTLOutput full
    HP_TENANTS=$(echo "${TCTL_OUTPUT}" | sed -n -e '/^NAME/,$p')
    deleteTCTLJob
    if deployTCTL "get tenant -o json"; then
      getTCTLOutput full
      HP_TENANTS_JSON=$(extractTctlJsonFromLogText <<< "${TCTL_OUTPUT}" | ${JQ_BIN} -c . 2>>"${HITT_ERR_FILE}" || echo '')
    else
      HP_TENANTS_JSON=''
    fi
    deleteTCTLJob
    deployTCTL "get service"
    getTCTLOutput full
    HP_SERVICES=$(echo "${TCTL_OUTPUT}" | sed -n -e '/^NAME/,$p')
    deleteTCTLJob
    if deployTCTL "get service -o json"; then
      getTCTLOutput full
      HP_SERVICES_JSON=$(extractTctlJsonFromLogText <<< "${TCTL_OUTPUT}" | ${JQ_BIN} -c . 2>>"${HITT_ERR_FILE}" || echo '')
    else
      HP_SERVICES_JSON=''
      HP_TENANTS_JSON=''
    fi
    deleteTCTLJob
  else
      HP_SERVICES_JSON=''
      HP_TENANTS_JSON=''
  fi
  logStatus "Gathering Helix Service Management information..." 1
  IS_VERSION=$(${KUBECTL_BIN} -n "${IS_NAMESPACE}" get sts platform-fts -o jsonpath='{.metadata.labels.chart}' 2>/dev/null | cut -f2 -d '-')
  if [ -z "${IS_VERSION}" ]; then
    IS_VERSION="not found"
  else
    buildISAliasesArray
    if isJenkinsInCluster ; then
      CONTAINERIZED_JENKINS=true
    else
      CONTAINERIZED_JENKINS=false
    fi
    checkJenkinsIsRunning
    UBER_VERSION=$(getPipelineParameterDefault HELIX_ONPREM_DEPLOYMENT PLATFORM_HELM_VERSION)
    getISDetailsFromK8s
    checkISRESTReady
    if [ "${IS_REST_READY}" == "1" ]; then
      checkISLicenseStatus
      getISDbID
    fi
    logPlatformFTSStartTime
    checkAssistTool
  fi
}

printInfo() {
  logStatus "BMC Helix Environment Summary" 1
  echo ""
  hittInfoPrintKv "Report created" "${NOW}"
  hittInfoPrintKv "Environment type" "${ENV_TYPE}"
  hittInfoPrintKv "Live environment" "${ENV_LIVE}"

  hittInfoPrintSection "Client information"
  hittInfoPrintKv "OS" "${OS_NAME:-unknown}"
  hittInfoPrintKv "Version" "${OS_VERSION:-unknown}"
  hittInfoPrintKv "kubectl" "${KUBECTL_VERSION:-unknown}"
  hittInfoPrintKv "Helm" "${HELM_VERSION:-unknown}"

  hittInfoPrintSection "Cluster information"
  hittInfoPrintKv "Kubernetes version" "${K8S_VERSION:-unknown}"
  hittInfoPrintKv "OpenShift version" "${OPENSHIFT_VERSION:-n/a}"

  hittInfoPrintSection "Node summary"
  printK8sNodeDetails || true

  hittInfoPrintSection "Ingress controller"
  printIngressControllerDetails

  hittInfoPrintSection "Helix Platform details"
  hittInfoPrintKv "Namespace" "${HP_NAMESPACE}"
  hittInfoPrintKv "Version" "${HP_VERSION}"
  hittInfoPrintKv "Deployment size" "${HP_DEPLOYMENT_SIZE}"
  hittInfoPrintKv "Load balancer host" "${LB_HOST}"
  hittInfoPrintKv "Portal URL" "${PORTAL_HOSTNAME}"
  echo ""
  echo "Tenants:"
  hittFormatTctlTableForDisplay "${HP_TENANTS}"
  echo ""
  echo "Services:"
  hittFormatTctlTableForDisplay "${HP_SERVICES}"

  hittInfoPrintSection "Helix Logging"
  hittInfoPrintKv "Namespace" "${HELIX_LOGGING_NAMESPACE:-n/a}"
  hittInfoPrintKv "Version" "${HELIX_LOGGING_VERSION:-n/a}"

  hittInfoPrintSection "Deployment Engine"
  hittInfoPrintKv "Containerized DE" "${CONTAINERIZED_JENKINS}"
  hittInfoPrintKv "Jenkins URL" "${JENKINS_LOG_URL}"
  hittInfoPrintKv "Jenkins version" "${JENKINS_VERSION}"
  hittInfoPrintKv "HELIX_ONPREM_DEPLOYMENT pipeline version" "${UBER_VERSION}"

  hittInfoPrintSection "Helix Service Management"
  hittInfoPrintKv "Namespace" "${IS_NAMESPACE}"
  hittInfoPrintKv "Version" "${IS_VERSION}"
  hittInfoPrintKv "IS db type:" "${IS_DB_TYPE}"
  hittInfoPrintKv "IS db ID" "${IS_DBID}"
  hittInfoPrintKv "IS license" "${IS_LICENSE_TYPE:-unknown}"
  hittInfoPrintKv "platform-fts-0 startup time" "${STARTUP_TIME}"
  hittInfoPrintKv "Support Assistant deployed" "$( [ "$SAT_DEPLOYED" = "1" ] && echo "true" || echo "false" )"
  echo ""
}

# Normalize tctl get tenant|service -o json into a JSON array for info.json (response shape varies by tctl version).
hittTctlListNormalizeForInfoJson() {
  local raw="${1:-}" out
  [[ -z "${raw}" ]] && echo '[]' && return 0
  out=$(printf '%s' "${raw}" | ${JQ_BIN} -c '
    if . == null then []
    elif type == "array" then .
    elif type == "object" and (.items | type) == "array" then .items
    elif type == "object" and (.tenants | type) == "array" then .tenants
    elif type == "object" and (.services | type) == "array" then .services
    elif type == "object" and (.data | type) == "array" then .data
    elif type == "object" then [.]
    else []
    end
  ' 2>>"${HITT_ERR_FILE}") || out='[]'
  printf '%s' "${out}" | hittJsonApplyInfoKeyNormalization 2>>"${HITT_ERR_FILE}" || echo '[]'
}

# Read JSON from stdin; write JSON with object keys normalized (strip "|", camelCase) and tctl pipe artifacts removed from string values.
hittJsonApplyInfoKeyNormalization() {
  ${JQ_BIN} -c '
    def hittStripPipeKey:
      gsub("\\|"; "")
      | gsub("^\\s+|\\s+$"; "");
    def hittSanitizeSegment:
      gsub("[^a-zA-Z0-9]"; "");
    def hittSnakeToCamel:
      split("_")
      | map(hittSanitizeSegment | gsub("^\\s+|\\s+$"; ""))
      | map(select(length > 0))
      | if length == 0 then ""
        elif length == 1 then
          (.[0]
           | if test("[a-z]") then (.[0:1] | ascii_downcase) + .[1:]
             elif test("^[A-Z0-9]+$") then ascii_downcase
             else (.[0:1] | ascii_downcase) + .[1:]
             end)
        else
          (.[0] | ascii_downcase) + (
            .[1:] | map(. as $seg
              | ($seg[0:1] | ascii_upcase) + ($seg[1:] | ascii_downcase)) | join("")
          )
        end;
    def hittNormalizeObjectKey:
      hittStripPipeKey
      | if . == "" then "_"
        elif test("_") then hittSnakeToCamel
        elif test("[a-z]") then (.[0:1] | ascii_downcase) + .[1:]
        else ascii_downcase
        end;
    walk(
      if type == "string" then
        gsub("^\\|+"; "")
        | gsub("\\|+$"; "")
        | gsub("^\\s+|\\s+$"; "")
        | gsub("\\s*\\|\\s*"; " ")
      elif type == "object" then
        with_entries(.key |= hittNormalizeObjectKey)
      else .
      end
    )
  ' 2>>"${HITT_ERR_FILE}"
}

# Convert a fixed-width, tab-, or pipe-separated table (header = column names) to a JSON array of objects.
# Empty or whitespace-only input yields [].
hittTableTextToJsonArray() {
  local raw="${1:-}"
  if [[ -z "${raw//[[:space:]]/}" ]]; then
    echo '[]'
    return 0
  fi
  printf '%s\n' "${raw}" | awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function jesc(s,   i, c, o) {
      o = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") o = o "\\\\"
        else if (c == "\"") o = o "\\\""
        else if (c == "\r") { }
        else if (c == "\n") o = o "\\n"
        else if (c == "\t") o = o "\\t"
        else o = o c
      }
      return o
    }
    function split_row(line, arr,   rest, nf) {
      delete arr
      nf = 0
      if (index(line, "\t") > 0) {
        nf = split(line, arr, "\t")
        for (i = 1; i <= nf; i++) arr[i] = trim(arr[i])
        return nf
      }
      # tctl get tenant|service tables often use | between columns
      if (index(line, "|") > 0) {
        nf = split(line, arr, "|")
        for (i = 1; i <= nf; i++) arr[i] = trim(arr[i])
        return nf
      }
      rest = line
      while (match(rest, /[[:space:]]{2,}/)) {
        if (RSTART > 1) arr[++nf] = trim(substr(rest, 1, RSTART - 1))
        rest = substr(rest, RSTART + RLENGTH)
      }
      if (length(trim(rest)) > 0) arr[++nf] = trim(rest)
      return nf
    }
    BEGIN { hdr = 0 }
    {
      line = trim($0)
      if (line == "") next
      if (!hdr) {
        n = split_row(line, keys)
        hdr = 1
        next
      }
      m = split_row(line, vals)
      printf "{"
      for (i = 1; i <= n && i <= m; i++) {
        if (i > 1) printf ","
        printf "\"%s\":\"%s\"", jesc(keys[i]), jesc(vals[i])
      }
      print "}"
    }
  ' | ${JQ_BIN} -s -c '.' 2>>"${HITT_ERR_FILE}" | hittJsonApplyInfoKeyNormalization 2>>"${HITT_ERR_FILE}" || echo '[]'
}

# writeInfoJson — emit the same facts as printInfo to a JSON file for support tooling.
# Output path: INFO_JSON_FILE (default: info.json in the current working directory).
writeInfoJson() {
  local out tab env_live helix_log sat cj node_rows tenants_rows services_rows
  out="${INFO_JSON_FILE:-info.json}"
  tab=$(printK8sNodeDetails 2>/dev/null || true)

  if [[ -n "${K8S_NODE_DETAILS_JSON:-}" ]] && echo "${K8S_NODE_DETAILS_JSON}" | ${JQ_BIN} -e 'type == "array"' >/dev/null 2>&1; then
    node_rows=$(echo "${K8S_NODE_DETAILS_JSON}" | ${JQ_BIN} -c . 2>>"${HITT_ERR_FILE}" || echo '[]')
  else
    node_rows=$(hittTableTextToJsonArray "${tab}")
  fi

  if [[ -n "${HP_TENANTS_JSON:-}" ]] && echo "${HP_TENANTS_JSON}" | ${JQ_BIN} -e . >/dev/null 2>&1; then
    tenants_rows=$(hittTctlListNormalizeForInfoJson "${HP_TENANTS_JSON}")
  else
    tenants_rows=$(hittTableTextToJsonArray "${HP_TENANTS:-}")
  fi

  if [[ -n "${HP_SERVICES_JSON:-}" ]] && echo "${HP_SERVICES_JSON}" | ${JQ_BIN} -e . >/dev/null 2>&1; then
    services_rows=$(hittTctlListNormalizeForInfoJson "${HP_SERVICES_JSON}")
  else
    services_rows=$(hittTableTextToJsonArray "${HP_SERVICES:-}")
  fi

  [[ -z "${node_rows}" ]] && node_rows='[]'
  [[ -z "${tenants_rows}" ]] && tenants_rows='[]'
  [[ -z "${services_rows}" ]] && services_rows='[]'

  if [[ "${ENV_LIVE}" == "true" ]]; then
    env_live=true
  else
    env_live=false
  fi
  if [[ "${HELIX_LOGGING_DEPLOYED:-}" == "1" ]]; then
    helix_log=true
  else
    helix_log=false
  fi
  if [[ "${SAT_DEPLOYED:-}" == "1" ]]; then
    sat=true
  else
    sat=false
  fi
  if [[ "${CONTAINERIZED_JENKINS:-}" == "true" ]]; then
    cj=true
  else
    cj=false
  fi

  if ! ${JQ_BIN} -n \
    --arg schemaVersion "1.4" \
    --arg reportCreated "${NOW}" \
    --arg environmentType "${ENV_TYPE:-}" \
    --argjson environmentLive "${env_live}" \
    --arg clientOsName "${OS_NAME:-}" \
    --arg clientOsVersion "${OS_VERSION:-}" \
    --arg clientKubectl "${KUBECTL_VERSION:-}" \
    --arg clientHelm "${HELM_VERSION:-}" \
    --arg clusterKubernetesVersion "${K8S_VERSION:-}" \
    --arg clusterOpenshiftVersion "${OPENSHIFT_VERSION:-}" \
    --argjson nodeSummary "${node_rows}" \
    --arg ingressHelixClass "${HP_INGRESS_CLASS:-}" \
    --arg ingressResolvedClassName "${INGRESS_CLASS_NAME:-}" \
    --arg ingressSpecController "${INGRESS_CLASS_SPEC_CONTROLLER:-}" \
    --arg ingressWorkloadType "${INGRESS_CONTROLLER_TYPE:-}" \
    --arg ingressControllerNamespace "${INGRESS_CONTROLLER_NAMESPACE:-}" \
    --arg ingressControllerName "${INGRESS_CONTROLLER_NAME:-}" \
    --arg ingressControllerImage "${INGRESS_CONTROLLER_IMAGE:-}" \
    --arg ingressClassesKubectl "${INGRESS_CLASSES:-}" \
    --arg helixPlatformNamespace "${HP_NAMESPACE:-}" \
    --arg helixPlatformVersion "${HP_VERSION:-}" \
    --arg helixPlatformDeploymentSize "${HP_DEPLOYMENT_SIZE:-}" \
    --arg helixPlatformLbHost "${LB_HOST:-}" \
    --arg helixPlatformPortalUrl "${PORTAL_HOSTNAME:-}" \
    --argjson helixPlatformTenants "${tenants_rows}" \
    --argjson helixPlatformServices "${services_rows}" \
    --arg helixLoggingNamespace "${HELIX_LOGGING_NAMESPACE:-}" \
    --arg helixLoggingVersion "${HELIX_LOGGING_VERSION:-}" \
    --argjson deploymentEngineContainerized "${cj}" \
    --arg deploymentEngineJenkinsUrl "${JENKINS_LOG_URL:-}" \
    --arg deploymentEngineJenkinsVersion "${JENKINS_VERSION:-}" \
    --arg deploymentEnginePipelineHelmVersion "${UBER_VERSION:-}" \
    --arg helixSmNamespace "${IS_NAMESPACE:-}" \
    --arg helixSmVersion "${IS_VERSION:-}" \
    --arg helixSmDbType "${IS_DB_TYPE:-}" \
    --arg helixSmDbId "${IS_DBID:-}" \
    --arg helixSmLicense "${IS_LICENSE_TYPE:-}" \
    --arg helixSmPlatformFtsStartup "${STARTUP_TIME:-}" \
    --argjson helixSmSupportAssistantDeployed "${sat}" \
    '{
      schemaVersion: $schemaVersion,
      reportCreated: $reportCreated,
      environment: {
        type: $environmentType,
        live: $environmentLive
      },
      client: {
        osName: $clientOsName,
        osVersion: $clientOsVersion,
        kubectl: $clientKubectl,
        helm: $clientHelm
      },
      cluster: {
        kubernetesVersion: $clusterKubernetesVersion,
        openshiftVersion: $clusterOpenshiftVersion
      },
      nodeSummary: $nodeSummary,
      ingress: {
        helixIngressClass: $ingressHelixClass,
        resolvedIngressClassName: $ingressResolvedClassName,
        ingressClassSpecController: $ingressSpecController,
        controllerWorkloadType: $ingressWorkloadType,
        controllerNamespace: $ingressControllerNamespace,
        controllerName: $ingressControllerName,
        controllerImage: $ingressControllerImage,
        ingressClassesKubectlOutput: $ingressClassesKubectl
      },
      helixPlatform: {
        namespace: $helixPlatformNamespace,
        version: $helixPlatformVersion,
        deploymentSize: $helixPlatformDeploymentSize,
        lbHost: $helixPlatformLbHost,
        portalUrl: $helixPlatformPortalUrl,
        tenants: $helixPlatformTenants,
        services: $helixPlatformServices
      },
      helixLogging: {
        namespace: $helixLoggingNamespace,
        version: $helixLoggingVersion
      },
      deploymentEngine: {
        containerizedJenkins: $deploymentEngineContainerized,
        jenkinsUrl: $deploymentEngineJenkinsUrl,
        jenkinsVersion: $deploymentEngineJenkinsVersion,
        helixOnpremDeploymentPipelineHelmVersion: $deploymentEnginePipelineHelmVersion
      },
      helixServiceManagement: {
        namespace: $helixSmNamespace,
        version: $helixSmVersion,
        isDbType: $helixSmDbType,
        isDbId: $helixSmDbId,
        isLicense: $helixSmLicense,
        platformFts0StartupTime: $helixSmPlatformFtsStartup,
        supportAssistantDeployed: $helixSmSupportAssistantDeployed
      }
    }' > "${out}" 2>>"${HITT_ERR_FILE}"; then
    logWarning "268" "Failed to write machine-readable environment summary to '${out}'."
    return 1
  fi
  logStatus "Machine-readable environment summary written to '${out}'." 1
  return 0
}

validateDockerIOPat() {
  local DOCKER_IO_USERNAME DOCKER_IO_PAT RESPONSE REGISTRY_JWT PAYLOAD_BASE64 REM DECODED_PAYLOAD ACTIONS
  local skip_registry_saved registry_username registry_password
  DOCKER_IO_USERNAME="${1:-}"
  DOCKER_IO_PAT="${2:-}"

  if [ -z "${DOCKER_IO_USERNAME}" ] && [ -z "${DOCKER_IO_PAT}" ]; then
    if [ -n "${HP_NAMESPACE}" ] && ${KUBECTL_BIN} -n "${HP_NAMESPACE}" get secret bmc-dtrhub &>/dev/null; then
      skip_registry_saved=${SKIP_REGISTRY:-0}
      getRegistryDetailsFromSecret "${HP_NAMESPACE}" "bmc-dtrhub"
      registry_username="${REGISTRY_USERNAME}"
      registry_password="${REGISTRY_PASSWORD}"
      SKIP_REGISTRY=${skip_registry_saved}
      if [[ -n "${registry_username}" && "${registry_username}" != "null" ]]; then
        if askYesNo "Use docker.io credentials from the Helix Platform namespace (username: ${registry_username})?"; then
          DOCKER_IO_USERNAME="${registry_username}"
          DOCKER_IO_PAT="${registry_password}"
        fi
      fi
    fi
  fi

  if [ -z "${DOCKER_IO_USERNAME}" ]; then
    read -r -p "Enter your docker.io username : " DOCKER_IO_USERNAME
    echo ""
    if [ -z "${DOCKER_IO_USERNAME}" ]; then
      logError "999" "Docker Hub username is required (pass on the command line or enter when prompted)." 1
    fi
  fi

  if [ -z "${DOCKER_IO_PAT}" ]; then
    read -r -s -p "Enter your PAT : " DOCKER_IO_PAT
    echo ""
  fi

  if [ -z "${DOCKER_IO_PAT}" ]; then
    logError "999" "Docker Hub PAT is required (pass on the command line or enter when prompted)." 1
  fi

  logMessage "Checking docker.io token scope for user '${DOCKER_IO_USERNAME}'..."

  # Request a registry token for private repository pull (bmchelix under this user)
  RESPONSE=$(${CURL_BIN} -s -u "${DOCKER_IO_USERNAME}:${DOCKER_IO_PAT}" \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${DOCKER_IO_USERNAME}/bmchelix:pull" 2>/dev/null)

  REGISTRY_JWT=$(echo "${RESPONSE}" | ${JQ_BIN} -r .token)

  if [ "${REGISTRY_JWT}" == "null" ] || [ -z "${REGISTRY_JWT}" ]; then
    logError "999" "Could not obtain a registry token. Check your username and PAT." 1
  fi

  PAYLOAD_BASE64=$(echo "${REGISTRY_JWT}" | cut -d'.' -f2)

  REM=$(( ${#PAYLOAD_BASE64} % 4 ))
  if [ ${REM} -eq 2 ]; then
    PAYLOAD_BASE64="${PAYLOAD_BASE64}=="
  elif [ ${REM} -eq 3 ]; then
    PAYLOAD_BASE64="${PAYLOAD_BASE64}="
  fi

  DECODED_PAYLOAD=$(echo "${PAYLOAD_BASE64}" | ${BASE64_BIN} --decode 2>/dev/null)

  ACTIONS=$(echo "${DECODED_PAYLOAD}" | ${JQ_BIN} -r ".access[0].actions[]?" 2>/dev/null || true)

  if echo "${ACTIONS}" | grep -q "pull"; then
    logMessage "Success: token grants pull scope for private repository '${DOCKER_IO_USERNAME}/bmchelix'."
  else
    logError "999" "Failed: token does not grant pull for private repository '${DOCKER_IO_USERNAME}/bmchelix' (often public-repo read-only). Update the PAT in Docker Hub / EPD." 1
  fi
}

# Kickstart manifests: kickstartManifestJsonBase() holds common overrides for all releases.
# Per-release additions: add kickstartManifestJsonDelta<ID>() (e.g. kickstartManifestJsonDelta26201).
# An empty delta ([]) registers the release and suppresses the unknown-release warning.
# Manifest id is derived from PLATFORM_HELM_VERSION major prefix: 2026201 -> 26201.
# Override delta id with HITT_KICKSTART_MANIFEST_ID (base is always applied).

kickstartManifestIdFromPlatformVersion() {
  # $1 = PLATFORM_HELM_VERSION from Jenkins (e.g. 2026201.1.00.00) -> manifest id (e.g. 26201)
  local platform_helm_version="$1"
  local major="${platform_helm_version%%.*}"
  if [[ "${major}" =~ ^20[0-9]{5}$ ]]; then
    echo "${major:2}"
    return 0
  fi
  logWarning "999" "Could not determine the HELIX_ONPREM_DEPLOYMENT release from pipeline defaults; using common kickstart values only."
  echo ""
}

kickstartHasManifestDelta() {
  declare -f "kickstartManifestJsonDelta${1}" &>/dev/null
}

kickstartGetManifestDeltaJson() {
  # $1 = manifest id, $2 = PLATFORM_HELM_VERSION (for messages). Prints delta JSON array to stdout.
  local manifest_id="$1" platform_helm_version="$2"
  if [ -z "${manifest_id}" ]; then
    echo '[]'
    return 0
  fi
  if kickstartHasManifestDelta "${manifest_id}"; then
    "kickstartManifestJsonDelta${manifest_id}"
    return 0
  fi
  logWarning "999" "No version-specific kickstart settings for HELIX_ONPREM_DEPLOYMENT release '${platform_helm_version}'; using common values only."
  echo '[]'
}

kickstartManifestJsonBase() {
  cat <<'EOF'
[
  { "param": "OS_RESTRICTED_SCC", "source": { "type": "handler", "name": "openshift_scc" } },
  { "param": "CLUSTER_CONTEXT", "source": { "type": "handler", "name": "cluster_context" } },
  { "param": "IS_NAMESPACE", "source": { "type": "var", "key": "IS_NAMESPACE" } },
  { "param": "CUSTOMER_SERVICE", "source": { "type": "var", "key": "IS_CUSTOMER_SERVICE" } },
  { "param": "ENVIRONMENT", "source": { "type": "var", "key": "IS_ENVIRONMENT" } },
  { "param": "INGRESS_CLASS", "source": { "type": "var", "key": "HP_INGRESS_CLASS" } },
  { "param": "CLUSTER_DOMAIN", "source": { "type": "var", "key": "CLUSTER_DOMAIN" } },
  { "param": "APPLICATION_PARENT_DOMAIN", "source": { "type": "var", "key": "CLUSTER_DOMAIN" } },
  { "param": "SIDECAR_FLUENTBIT", "source": { "type": "handler", "name": "sidecar_fluentbit" } },
  { "param": "HARBOR_REGISTRY_HOST", "source": { "type": "var", "key": "HP_REGISTRY_SERVER" } },
  { "param": "HARBOR_REGISTRY_ORG", "source": { "type": "var", "key": "HP_REGISTRY_PROJECT" } },
  { "param": "IMAGE_REGISTRY_USERNAME", "source": { "type": "var", "key": "HP_REGISTRY_USERNAME" } },
  { "param": "IMAGE_REGISTRY_PASSWORD", "source": { "type": "var", "key": "HP_REGISTRY_PASSWORD" } },
  { "param": "IMAGESECRET_NAME", "source": { "type": "literal", "value": "helixregsecret" } },
  { "param": "FTS_ELASTICSEARCH_HOSTNAME", "source": { "type": "handler", "name": "fts_hostname" } },
  { "param": "FTS_ELASTICSEARCH_PORT", "source": { "type": "literal", "value": "9200" } },
  { "param": "FTS_ELASTICSEARCH_USERNAME", "source": { "type": "var", "key": "LOG_ELASTICSEARCH_USERNAME" } },
  { "param": "FTS_ELASTICSEARCH_USER_PASSWORD", "source": { "type": "var", "key": "LOG_ELASTICSEARCH_PASSWORD" } },
  { "param": "FTS_ELASTICSEARCH_SECURE", "source": { "type": "literal", "value": "true" } },
  { "param": "RSSO_URL", "source": { "type": "var", "key": "RSSO_URL" } },
  { "param": "RSSO_ADMIN_USER", "source": { "type": "var", "key": "RSSO_USERNAME" } },
  { "param": "RSSO_ADMIN_PASSWORD", "source": { "type": "var", "key": "RSSO_PASSWORD" } },
  { "param": "TENANT_DOMAIN", "source": { "type": "var", "key": "HP_TENANT" } },
  { "param": "HELIX_PLATFORM_NAMESPACE", "source": { "type": "var", "key": "HP_NAMESPACE" } },
  { "param": "HELIX_PLATFORM_DOMAIN", "source": { "type": "var", "key": "CLUSTER_DOMAIN" } },
  { "param": "HELIX_PLATFORM_CUSTOMER_NAME", "source": { "type": "var", "key": "HP_COMPANY_NAME" } }
]
EOF
}

# Registered releases with no extra kickstart rows beyond kickstartManifestJsonBase.
kickstartManifestJsonDelta26201() {
  echo '[]'
}

kickstartMergeManifestJson() {
  # $1 = base JSON array, $2 = delta JSON array. Delta entries override base for the same param.
  ${JQ_BIN} -n --argjson base "${1}" --argjson delta "${2}" '
    ($base + $delta)
    | group_by(.param)
    | map(last)
  '
}

kickstartResolveHandler() {
  case "${1}" in
    openshift_scc)
      [ "${OPENSHIFT}" = "1" ] && echo true || echo false
      ;;
    cluster_context)
      ${KUBECTL_BIN} config current-context 2>/dev/null
      ;;
    sidecar_fluentbit)
      [ "${HELIX_LOGGING_DEPLOYED}" = "1" ] && echo true || echo false
      ;;
    fts_hostname)
      echo "${FTS_ELASTIC_SERVICENAME}.${HP_NAMESPACE}"
      ;;
    *)
      logError "999" "Unknown kickstart handler '${1}'." 1
      ;;
  esac
}

kickstartResolveSource() {
  # $1 = source object JSON from manifest row
  local source_type source_key handler_name value
  source_type=$(${JQ_BIN} -r '.type' <<< "${1}")
  case "${source_type}" in
    var)
      source_key=$(${JQ_BIN} -r '.key' <<< "${1}")
      echo "${!source_key}"
      ;;
    literal)
      ${JQ_BIN} -r '.value' <<< "${1}"
      ;;
    handler)
      handler_name=$(${JQ_BIN} -r '.name' <<< "${1}")
      if ! value=$(kickstartResolveHandler "${handler_name}"); then
        return 1
      fi
      printf '%s' "${value}"
      ;;
    *)
      logError "999" "Unknown kickstart source type '${source_type}'." 1
      ;;
  esac
}

kickstartAddOverride() {
  # $1 = Jenkins param name, $2 = value. Updates KICKSTART_OVERRIDES_JSON.
  [ -z "${2}" ] && return 0
  KICKSTART_OVERRIDES_JSON=$(${JQ_BIN} -c --arg k "${1}" --arg v "${2}" '. + {($k): $v}' <<< "${KICKSTART_OVERRIDES_JSON}")
}

kickstartResolveManifest() {
  local manifest_id manifest_json base_json delta_json manifest_row param source_json value pipeline_defaults_json platform_helm_version resolved_count skipped_count manifest_scope
  if ! pipeline_defaults_json=$(getPipelineDefaults HELIX_ONPREM_DEPLOYMENT); then
    return 1
  fi
  platform_helm_version=$(${JQ_BIN} -r '.PLATFORM_HELM_VERSION // empty' <<< "${pipeline_defaults_json}")
  if [ -z "${platform_helm_version}" ]; then
    logError "999" "Unable to read PLATFORM_HELM_VERSION from HELIX_ONPREM_DEPLOYMENT pipeline defaults." 1
  fi
  if [ -n "${HITT_KICKSTART_MANIFEST_ID}" ]; then
    manifest_id="${HITT_KICKSTART_MANIFEST_ID}"
    logMessage "Using kickstart release id '${manifest_id}' (HITT_KICKSTART_MANIFEST_ID override)." 1
  else
    manifest_id=$(kickstartManifestIdFromPlatformVersion "${platform_helm_version}")
  fi
  base_json=$(kickstartManifestJsonBase)
  if ! delta_json=$(kickstartGetManifestDeltaJson "${manifest_id}" "${platform_helm_version}"); then
    return 1
  fi
  if ! manifest_json=$(kickstartMergeManifestJson "${base_json}" "${delta_json}"); then
    return 1
  fi
  if ! ${JQ_BIN} -e 'type == "array"' <<< "${manifest_json}" &>/dev/null; then
    logError "999" "Kickstart manifest must be a JSON array." 1
  fi
  if [ -n "${manifest_id}" ] && kickstartHasManifestDelta "${manifest_id}"; then
    manifest_scope="common + release ${manifest_id}"
  else
    manifest_scope="common"
  fi
  KICKSTART_OVERRIDES_JSON='{}'
  resolved_count=0
  skipped_count=0
  while IFS= read -r manifest_row; do
    param=$(${JQ_BIN} -r '.param' <<< "${manifest_row}")
    if ! ${JQ_BIN} -e --arg p "${param}" 'has($p)' <<< "${pipeline_defaults_json}" &>/dev/null; then
      skipped_count=$((skipped_count + 1))
      continue
    fi
    source_json=$(${JQ_BIN} -c '.source' <<< "${manifest_row}")
    if ! value=$(kickstartResolveSource "${source_json}"); then
      return 1
    fi
    if [ -n "${value}" ]; then
      kickstartAddOverride "${param}" "${value}"
      resolved_count=$((resolved_count + 1))
    fi
  done < <(${JQ_BIN} -c '.[]' <<< "${manifest_json}")
  logMessage "Kickstart manifest (${manifest_scope}, pipeline ${platform_helm_version}): ${resolved_count} parameter override(s) (${skipped_count} skipped — not on this job)." 1
  KICKSTART_PIPELINE_DEFAULTS_JSON="${pipeline_defaults_json}"
}

kickstartGatherPlatformContext() {
  checkToolVersion kubectl
  getVersions
  setVarsFromPlatform
  getDomain
  getRSSODetails
  getTenantDetails
  checkHelixLoggingDeployed
  getRegistryDetailsFromHP
}

# hittPipelineJsonForKickstartExport job_name json_object
#   Removes file upload parameters and INPUT_CONFIG_METHOD; sets every PIPELINES-section
#   boolean parameter to "false" (same intent as build/kickstart queue prep).
hittPipelineJsonForKickstartExport() {
  local job_name="${1:-HELIX_ONPREM_DEPLOYMENT}"
  local input_json="$2"
  local pipeline_file_params_json pipeline_section_params_json

  pipeline_file_params_json=$(getPipelineFileParams "${job_name}")
  if ! echo "${pipeline_file_params_json}" | ${JQ_BIN} -e 'type == "array"' &>/dev/null; then
    logError "999" "Unable to discover file parameters from Jenkins job '${job_name}'." 1
  fi
  pipeline_section_params_json=$(getPipelineSectionParams "${job_name}")
  if ! echo "${pipeline_section_params_json}" | ${JQ_BIN} -e 'type == "array"' &>/dev/null; then
    logError "999" "Unable to discover PIPELINES section parameters from Jenkins job '${job_name}'." 1
  fi

  ${JQ_BIN} -n \
    --argjson file_params "${pipeline_file_params_json}" \
    --argjson pipeline_params "${pipeline_section_params_json}" \
    --arg input "${input_json}" \
    '($input | fromjson)
     | reduce $file_params[] as $name (.; del(.[$name]))
     | del(.INPUT_CONFIG_METHOD)
     | reduce $pipeline_params[] as $name (. ; . + {($name): "false"})'
}

kickstartMergedPipelineJson() {
  local merged_json export_json
  kickstartResolveManifest || return 1
  if ! merged_json=$(${JQ_BIN} -n \
    --arg defaults "${KICKSTART_PIPELINE_DEFAULTS_JSON}" \
    --arg overrides "${KICKSTART_OVERRIDES_JSON}" \
    '($defaults | fromjson) * ($overrides | fromjson)'); then
    return 1
  fi
  if ! export_json=$(hittPipelineJsonForKickstartExport HELIX_ONPREM_DEPLOYMENT "${merged_json}"); then
    return 1
  fi
  KICKSTART_MERGED_JSON="${export_json}"
}

kickStartUberPipeline() {
  kickstartResolveManifest || exit 1
  PIPELINE_INPUT_JSON="${KICKSTART_OVERRIDES_JSON}"
  triggerHelixOnpremPipelineBuild "kickstart discovery"
}

checkCDE() {
  if isJenkinsInCluster && [[ "${UBER_VERSION}" =~ ^2021 ]]; then
      logError "999" "Unexpected HELIX_ONPREM_DEPLOYMENT pipeline version '${UBER_VERSION}' - check pipeline console output for errors during dry run build."
  else
    logMessage "HELIX_ONPREM_DEPLOYMENT pipeline version '${UBER_VERSION}'."
  fi

  if [ "${HP_CUSTOM_CERT}" == "true" ] && [[ "${UBER_VERSION}" =~ "2026201" ]]; then
    if ! ${KUBECTL_BIN} -n "${CDE_NAMESPACE}" get secret jenkins-custom-ca >/dev/null 2>&1 ; then
      logError "999" "Custom CA certificate in use but Jenkins was deployed with CUSTOM_CA=false in deployment-engine-config.env"
    fi
  fi

}

# Catalog columns: profile|severity|scope|verb|resource|description
# profile: all (shared reads), hitt (triage/fix), deploy (install/upgrade/pipelines)
_hittK8sProfileMatches() {
  local row_profile=$1
  local active_profile=$2
  case "${active_profile}" in
    all) return 0 ;;
    hitt) [[ "${row_profile}" == "all" || "${row_profile}" == "hitt" ]] ;;
    deploy) [[ "${row_profile}" == "all" || "${row_profile}" == "deploy" ]] ;;
    *) return 1 ;;
  esac
}

_hittK8sEmitDeployCatalogRows() {
  local resource verb
  local -a deploy_resources=(
    deployments services secrets configmaps persistentvolumeclaims
    ingresses jobs serviceaccounts roles rolebindings
    statefulsets daemonsets cronjobs
  )
  local -a deploy_verbs=(create update patch get list delete)
  for resource in "${deploy_resources[@]}"; do
    for verb in "${deploy_verbs[@]}"; do
      printf 'deploy|required|helix-ns|%s|%s|Helix deploy — %s %s (DE / pipeline / deployment-manager)\n' \
        "${verb}" "${resource}" "${verb}" "${resource}"
    done
  done
  for verb in get list watch; do
    printf 'deploy|required|helix-ns|%s|pods|Helix deploy — pods %s (SAT / rollout checks)\n' "${verb}" "${verb}"
  done
  printf 'deploy|required|helix-ns|get|pods/log|Helix deploy — read pod logs during install\n'
  for verb in get list patch update create delete; do
    printf 'deploy|optional|helix-ns|%s|horizontalpodautoscalers|Helix deploy — HPA %s (scale / sizing)\n' \
      "${verb}" "${verb}"
  done
}

_hittK8sHelixNamespaces() {
  local -a helix_ns=()
  local n existing seen
  for n in "${HP_NAMESPACE}" "${IS_NAMESPACE}" "${CDE_NAMESPACE}" "${HELIX_LOGGING_NAMESPACE}"; do
    [[ -z "${n}" ]] && continue
    seen=0
    for existing in "${helix_ns[@]}"; do
      [[ "${existing}" == "${n}" ]] && seen=1 && break
    done
    (( seen )) || helix_ns+=("${n}")
  done
  ((${#helix_ns[@]})) && printf '%s\n' "${helix_ns[@]}"
}

hittK8sPermissionsCatalog() {
  cat <<'EOF'
all|required|cluster|get|nodes|Read node status (info cluster, health checks)
all|required|cluster|list|nodes|List nodes
all|required|cluster|get|namespaces|Validate and discover namespaces
all|required|cluster|list|namespaces|List namespaces (config bootstrap)
all|required|cluster|get|ingressclasses|Read IngressClass objects
all|required|cluster|list|ingressclasses|List IngressClasses
all|required|all-ns|get|pods|Read pods cluster-wide (node summary, health checks)
all|required|all-ns|list|pods|List pods in all namespaces
all|required|all-ns|get|deployments|Read Deployments (namespace validation, ingress discovery)
all|required|all-ns|list|deployments|List Deployments cluster-wide
all|required|all-ns|get|daemonsets|Read DaemonSets (ingress controller discovery)
all|required|all-ns|list|daemonsets|List DaemonSets cluster-wide
all|required|all-ns|get|statefulsets|Read StatefulSets (IS platform checks)
all|required|all-ns|list|statefulsets|List StatefulSets
all|required|all-ns|get|jobs|Read Jobs (tctl / sealtctl)
all|required|all-ns|list|jobs|List Jobs
all|required|all-ns|get|secrets|Read Secrets (credentials, cacerts, registry)
all|required|all-ns|list|secrets|List Secrets
all|required|all-ns|get|configmaps|Read ConfigMaps (Helix config, utility export)
all|required|all-ns|list|configmaps|List ConfigMaps
all|required|all-ns|get|ingresses|Read Ingress hostnames and routing
all|required|all-ns|list|ingresses|List Ingresses
all|required|all-ns|get|services|Read Services (LB hosts, connectivity checks)
all|required|all-ns|list|services|List Services
all|required|all-ns|get|resourcequotas|Read namespace ResourceQuotas
all|required|all-ns|list|resourcequotas|List ResourceQuotas
all|required|all-ns|get|roles|Read Roles (Support Assistant Tool check)
all|required|all-ns|list|roles|List Roles
all|required|all-ns|get|rolebindings|Read RoleBindings
all|required|all-ns|list|rolebindings|List RoleBindings
all|required|all-ns|get|events|Read namespace Events (diagnostic logs)
all|required|all-ns|list|events|List Events
all|required|all-ns|get|pods/log|Read pod and job logs
hitt|optional|metrics|get|nodes.metrics.k8s.io|Node CPU/memory via kubectl top nodes
hitt|optional|metrics|list|nodes.metrics.k8s.io|List node metrics
hitt|optional|openshift|get|clusteroperators|Detect OpenShift clusters
hitt|optional|openshift|list|clusteroperators|List OpenShift cluster operators
hitt|optional|openshift|get|clusterversion|Read OpenShift cluster version
hitt|optional|openshift|list|clusterversion|List OpenShift cluster versions
hitt|optional|all-ns|create|pods/exec|Exec into pods (DB/ES health checks, ping utility)
hitt|required|helix-ns|delete|jobs|Delete tctl/sealtctl jobs after use
hitt|required|helix-ns|create|jobs|Create tctl/sealtctl jobs
hitt|required|helix-ns|patch|jobs|Apply/update tctl jobs (kubectl apply)
hitt|required|helix-ns|delete|secrets|Replace IS cacerts secret (fix cacerts)
hitt|required|helix-ns|create|secrets|Create IS cacerts secret (fix cacerts)
hitt|required|helix-ns|patch|secrets|Apply updated secrets (fix cacerts)
hitt|required|helix-ns|create|roles|Create assisttool-rl role (fix sat)
hitt|required|helix-ns|create|rolebindings|Create assisttool-rlb binding (fix sat)
EOF
  _hittK8sEmitDeployCatalogRows
}

_hittK8sCanI() {
  local verb=$1
  local resource=$2
  shift 2
  ${KUBECTL_BIN} auth can-i "${verb}" "${resource}" "$@" --quiet 2>>"${HITT_ERR_FILE}"
}

_hittK8sLogPermissionCheck() {
  # $1=severity $2=scope $3=verb $4=resource $5=granted $6=desc $7=namespace (optional)
  [[ "${VERBOSITY}" -lt 1 ]] || [[ "${QUIET}" != "0" ]] && return
  if [[ -n "${7:-}" ]]; then
    logMessage "${1} ${3} ${4} (${2}, namespace '${7}'): ${5}" 1
  else
    logMessage "${1} ${3} ${4} (${2}): ${5}" 1
  fi
}

validateHittK8sPermissions() {
  local active_profile="${1:-hitt}"
  local required denied optional_denied skipped checked
  local profile req scope verb resource desc granted ns ns_granted ns_logged _ln
  local -a helix_ns=()
  local -a rbac_logged_ns=()
  local -a missing_required=()
  local -a missing_optional=()
  local -a skipped_checks=()

  case "${active_profile}" in
    hitt|deploy|all) ;;
    *)
      logError "999" "Unknown RBAC profile '${active_profile}' — use hitt, deploy, or all." 1
      ;;
  esac

  if ! ${KUBECTL_BIN} version --request-timeout=5s >/dev/null 2>>"${HITT_ERR_FILE}"; then
    logError "999" "Unable to reach the Kubernetes API with '${KUBECTL_BIN}' — check kubeconfig and cluster connectivity."
    return 1
  fi
  mapfile -t helix_ns < <(_hittK8sHelixNamespaces)

  if [[ "${active_profile}" == "deploy" || "${active_profile}" == "all" ]] && ((${#helix_ns[@]} == 0)); then
    logError "999" "Profile '${active_profile}' needs Helix namespaces in hitt.conf (HP_NAMESPACE, IS_NAMESPACE, and optionally CDE_NAMESPACE / HELIX_LOGGING_NAMESPACE) before deploy permissions can be checked." 1
  fi

  logStatus "Kubernetes RBAC audit (profile: ${active_profile})..."
  logMessage  "User: $(${KUBECTL_BIN} config view --minify -o jsonpath='{.contexts[0].context.user}' 2>/dev/null || echo unknown)"
  logMessage  "Context: $(${KUBECTL_BIN} config current-context 2>/dev/null || echo unknown)"
  if ((${#helix_ns[@]} > 0)); then
    logMessage "Helix namespaces: ${helix_ns[*]}"
  else
    logWarning "999" "Helix namespaces: (none — set HP_NAMESPACE / IS_NAMESPACE / CDE_NAMESPACE in hitt.conf to validate namespace-scoped permissions)"
  fi
  echo ""

  required=0
  denied=0
  optional_denied=0
  skipped=0
  checked=0

  while IFS='|' read -r profile req scope verb resource desc; do
    [[ -z "${profile}" ]] && continue
    _hittK8sProfileMatches "${profile}" "${active_profile}" || continue
    granted="yes"
    checked=$((checked + 1))

    case "${scope}" in
      cluster|metrics|openshift)
        if ! _hittK8sCanI "${verb}" "${resource}"; then
          granted="no"
        fi
        _hittK8sLogPermissionCheck "${req}" "${scope}" "${verb}" "${resource}" "${granted}" "${desc}"
        ;;
      all-ns)
        if ! _hittK8sCanI "${verb}" "${resource}" --all-namespaces; then
          granted="no"
        fi
        _hittK8sLogPermissionCheck "${req}" "${scope}" "${verb}" "${resource}" "${granted}" "${desc}"
        ;;
      helix-ns)
        if ((${#helix_ns[@]} == 0)); then
          granted="skip"
          skipped=$((skipped + 1))
          skipped_checks+=("${verb}|${resource}|helix-ns|no namespaces configured|${desc}")
        else
          for ns in "${helix_ns[@]}"; do
            ns_logged=0
            for _ln in "${rbac_logged_ns[@]}"; do
              [[ "${_ln}" == "${ns}" ]] && ns_logged=1 && break
            done
            if (( ! ns_logged )); then
              logMessage "Checking permissions for namespace - '${ns}'"
              rbac_logged_ns+=("${ns}")
            fi
            ns_granted="yes"
            if ! _hittK8sCanI "${verb}" "${resource}" -n "${ns}"; then
              ns_granted="no"
              granted="no (${ns})"
            fi
            _hittK8sLogPermissionCheck "${req}" "${scope}" "${verb}" "${resource}" "${ns_granted}" "${desc}" "${ns}"
            [[ "${granted}" != "yes" ]] && break
          done
        fi
        ;;
      *)
        granted="skip"
        skipped=$((skipped + 1))
        ;;
    esac

    if [[ "${granted}" == "skip" ]]; then
      continue
    fi

    if [[ "${req}" == "required" ]]; then
      required=$((required + 1))
      if [[ "${granted}" != "yes" ]]; then
        denied=$((denied + 1))
        missing_required+=("${verb}|${resource}|${scope}|${granted}|${desc}")
      fi
    else
      if [[ "${granted}" != "yes" ]]; then
        optional_denied=$((optional_denied + 1))
        missing_optional+=("${verb}|${resource}|${scope}|${granted}|${desc}")
      fi
    fi
  done < <(hittK8sPermissionsCatalog)

  if ((checked == 0)); then
    logError "999" "No RBAC checks matched profile '${active_profile}'."
    return 1
  fi

  if ((${#missing_required[@]} > 0)); then
    echo "Missing required permissions (${#missing_required[@]}):"
    echo ""
    {
      printf '%s\n' 'VERB|RESOURCE|SCOPE|STATUS|DESCRIPTION'
      printf '%s\n' "${missing_required[@]}"
    } | column -s '|' -t
    echo ""
  fi

  if ((${#missing_optional[@]} > 0)); then
    echo "Missing optional permissions (${#missing_optional[@]} — some features may be degraded):"
    echo ""
    {
      printf '%s\n' 'VERB|RESOURCE|SCOPE|STATUS|DESCRIPTION'
      printf '%s\n' "${missing_optional[@]}"
    } | column -s '|' -t
    echo ""
  fi

  if ((${#skipped_checks[@]} > 0)); then
    echo "Not checked (${#skipped_checks[@]} — configure Helix namespaces in hitt.conf to include namespace-scoped rules):"
    echo ""
    {
      printf '%s\n' 'VERB|RESOURCE|SCOPE|STATUS|DESCRIPTION'
      printf '%s\n' "${skipped_checks[@]}"
    } | column -s '|' -t
    echo ""
  fi

  if ((${denied} > 0)); then
    logError "999" "${denied} required Kubernetes permission(s) are not granted for profile '${active_profile}'."
    return 1
  fi
  if ((${#skipped_checks[@]} > 0)); then
    logStatus "Kubernetes RBAC audit (${active_profile}) complete — ${checked} check(s) run; all required permissions granted; ${#skipped_checks[@]} namespace-scoped check(s) skipped." 0
  else
    logStatus "Kubernetes RBAC audit (${active_profile}) complete — ${checked} check(s) run; all required permissions granted." 0
  fi
  return 0
}

getJenkinsAgentLog() {
  "${CURL_BIN}" --max-time 10 -b .cookies -sk -H "Jenkins-Crumb:${JENKINS_CRUMB}" "${JENKINS_URL}/computer/jenkins-agent/logText/progressiveText?start=0"
}

getJenkinsSystemLog() {
  SCRIPT='import java.util.logging.LogManager
    import java.util.logging.LogRecord
    import hudson.util.RingBufferLogHandler
    import java.text.SimpleDateFormat

    def formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    def rootLogger = LogManager.getLogManager().getLogger("")
    def handler = rootLogger.getHandlers().find { it instanceof RingBufferLogHandler }

    if (handler == null) {
        println "No RingBufferLogHandler found on root logger."
        return
    }

    List<LogRecord> records = handler.getView()

    records.reverse().each { LogRecord r ->
        def time = formatter.format(new Date(r.millis))
        def level = r.level.getName()
        def logger = r.loggerName
        def msg = r.message
        println "[$time][$level][$logger] $msg"
        if (r.thrown != null) {
            def sw = new StringWriter()
            r.thrown.printStackTrace(new PrintWriter(sw))
            println sw.toString()
        }
    }'
runJenkinsScript "${SCRIPT}"
}

# Requires
listImageTags() {
  local host SKOPEO_JSON
  if ! which skopeo >/dev/null 2>&1; then
    logError "999" "'imagels' requires skopeo to be installed - see https://skopeo.org/#download"
  fi
  host="${SKOPEO_IMAGE%%/*}"
  if ! skopeo login --get-login "${host}" >/dev/null 2>&1; then
    logError "999" "Please use 'skopeo login ${host}' to authenticate and then try again." 1
  fi
  SKOPEO_JSON=$(skopeo list-tags "docker://${SKOPEO_IMAGE}" 2>/dev/null)
  if [ "$?" != "0" ]; then
    logError "999" "Error listing repository tags: repository '${SKOPEO_IMAGE}' not found"
  else
    echo "${SKOPEO_JSON}" | ${JQ_BIN}
  fi
}

enumerateHelixVersions() {
  NS_ARRAY=($(${KUBECTL_BIN} get ns --no-headers -o custom-columns=':.metadata.name'))
  discoverHelixNamespaceCandidates
  if [ "${#HP_NS_CANDIDATES[@]}" -gt 0 ]; then
    logStatus "Helix Platform"
    for n in "${HP_NS_CANDIDATES[@]}"; do
      HP_VERSION=$(${KUBECTL_BIN} -n "${n}" get cm helix-on-prem-config -o jsonpath='{.data.version}' | head -1)
      [[ "${n}" == "${HP_NAMESPACE}" ]] && n="${n}*"
      echo -e "${n}\t\t${HP_VERSION:-unknown}"
    done
  fi
  if [ "${#IS_NS_CANDIDATES[@]}" -gt 0 ]; then
    logStatus "Helix IS"
    for n in "${IS_NS_CANDIDATES[@]}"; do
      IS_VERSION=$(${KUBECTL_BIN} -n "${n}" get sts platform-fts -o jsonpath='{.metadata.labels.chart}' | cut -d'-' -f2)
      [[ "${n}" == "${IS_NAMESPACE}" ]] && n="${n}*"
      echo -e "${n}\t\t${IS_VERSION:-unknown}"
    done
  fi
  if [ "${#CDE_NS_CANDIDATES[@]}" -gt 0 ]; then
    logStatus "Containerized Deployment Engine"
    for n in "${CDE_NS_CANDIDATES[@]}"; do
      CDE_VERSION=$(${KUBECTL_BIN} -n "${n}" get deployments.apps gitea -o jsonpath='{.metadata.labels.helix-de/version}')
      [[ "${n}" == "${CDE_NAMESPACE}" ]] && n="${n}*"
      echo -e "${n}\t\t${CDE_VERSION:-unknown}"
    done
  fi
  if [ "${#HL_NS_CANDIDATES[@]}" -gt 0 ]; then
    logStatus "Helix Logging"
    for n in "${HL_NS_CANDIDATES[@]}"; do
      echo -e "${n}"
    done
  fi
}

#End functions

# MAIN Start
main() {

NOW=$(date)
logStatus "Welcome to the Helix IS Triage Tool (build ${HITT_BUILD_VERSION}) - ${NOW}."
logStatus "Using config file '${HITT_CONFIG_FILE}'."
logStatus "Checking KUBECONFIG file..."
checkKubeconfig

# config file checks
if [ ! -f "${HITT_CONFIG_FILE}" ] && [ "${MODEARGS[*]}" == "info helix" ]; then
  # Catch "info helix" and allow to run without hitt.conf
  SKIP_UPDATE_CHECK=1
elif [ ! -f "${HITT_CONFIG_FILE}" ]; then
  if ! ${KUBECTL_BIN} get ns > /dev/null 2>&1 ; then
    createHITTconf "${HITT_CONFIG_FILE}"
    logError "199" "'kubectl get namespaces' command returned unexpected results - please update the HITT config file '${HITT_CONFIG_FILE}' manually." 1
  fi
  NS_ARRAY=($(${KUBECTL_BIN} get ns --no-headers -o custom-columns=':.metadata.name'))
  logStatus "HITT config file '${HITT_CONFIG_FILE}' not found - creating..."
  logStatus "Please use the following steps to configure the HITT script and create your config file..."
  getConfValues
  createHITTconf "${HITT_CONFIG_FILE}"
else
  if [ -f .hitt.conf ] && [ ! -w .hitt.conf ]; then
    logError "228" "The '.hitt.conf' file is not writable by the current user - please make sure all files in the hitt directory are owned by the user running the HITT script." 1
  fi
  createHITTconf ".hitt.conf"
  checkHITTconf "${HITT_CONFIG_FILE}"
fi

[[ -f "./${HITT_CONFIG_FILE}" ]] && source "./${HITT_CONFIG_FILE}"

# Conf overrides
if [ "${CONF_OVERRIDE}" == "1" ]; then
  for opt in HP_NAMESPACE IS_NAMESPACE CDE_NAMESPACE IS_ENVIRONMENT IS_CUSTOMER_SERVICE JENKINS_USERNAME JENKINS_PASSWORD; do
    var="${opt}_OVERRIDE"
    if [ "${!var}" != "" ]; then
      printf -v "${opt}" '%s' "${!var}"
    fi
  done
fi

# Proxy settings
if [ "${https_proxy}" != "" ] && [ "${DISABLE_PROXY}" == "0" ]; then
  logMessage "Proxy environment variables are set - run HITT with -x option to ignore them."
  PROXY_STRING="${https_proxy#*://}" # strip https://
  PROXY_STRING="${PROXY_STRING%/}" # strip any trailing /
  # authentication required?
  if echo "${https_proxy}" | grep -q "@" ; then
    PROXY_CREDS="${PROXY_STRING%@*}"
    PROXY_USER="${PROXY_CREDS%:*}"
    PROXY_PWD="${PROXY_CREDS#*:}"
    PROXY_STRING="${PROXY_STRING#*@}"
    PROXY_HOST="${PROXY_STRING%%:*}"
    JAVA_PROXY_CREDS="-Dhttps.proxyUser=${PROXY_USER} -Dhttps.proxyPassword=${PROXY_PWD}"
    OPENSSL_PROXY_CREDS="-proxy_user ${PROXY_USER} -proxy_pass pass:${PROXY_PWD}"
  else
    PROXY_HOST="${PROXY_STRING%%:*}"
  fi
  if [ "${no_proxy}" != "" ]; then
    #JAVA_NO_PROXY_HOSTS=$(echo ${no_proxy} | tr ',' '|')
    JAVA_NO_PROXY_HOSTS=$(echo ${no_proxy} | tr ',' ' ' | tr -s ' ' | tr ' ' '|')
    JAVA_NO_PROXY_STRING="-Dhttp.nonProxyHosts=${JAVA_NO_PROXY_HOSTS}"
  fi
  PROXY_PORT="${PROXY_STRING##*:}"
  JAVA_PROXY_STRING="-Dhttps.proxyHost=${PROXY_HOST} -Dhttps.proxyPort=${PROXY_PORT} ${JAVA_PROXY_CREDS} ${JAVA_NO_PROXY_STRING}"
  OPENSSL_PROXY_STRING="-proxy ${PROXY_HOST}:${PROXY_PORT} ${OPENSSL_PROXY_CREDS}"
else
  JAVA_PROXY_STRING=""
  OPENSSL_PROXY_STRING=""
fi

checkForNewHITT
checkCLITools

# Make Jenkins credentials URL safe
if [ "${JENKINS_USERNAME}" == "" ] && [ "${JENKINS_PASSWORD}" != "" ]; then
  logError "219" "JENKINS_PASSWORD is set but JENKINS_USERNAME is blank.  Please set both values in the hitt.conf file." 1
fi
if [ -n "${JENKINS_USERNAME}" ]; then
  JENKINS_PASSWORD=$(printf %s "${JENKINS_PASSWORD}" | ${JQ_BIN} -sRr @uri)
  JENKINS_CREDENTIALS="${JENKINS_USERNAME}:${JENKINS_PASSWORD}@"
fi

# Build JENKINS_URL
JENKINS_URL="${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}:${JENKINS_PORT}"
if [ "${JENKINS_PROTOCOL}" == "https" ] && [ "${JENKINS_PORT}" == "443" ]; then
  JENKINS_URL="${JENKINS_PROTOCOL}://${JENKINS_CREDENTIALS}${JENKINS_HOSTNAME}"
  JENKINS_LOG_URL="${JENKINS_PROTOCOL}://${JENKINS_HOSTNAME}"
fi
if [ -n "${JENKINS_URL_OVERRIDE}" ]; then
  JENKINS_URL="${JENKINS_URL_OVERRIDE}"
fi

# Remove old files
cleanUp start

# Run tctl command and then exit
if [[ ! -z "${TCTL_CMD}" ]]; then
  logStatus "Running in tctl mode..."
  checkToolVersion kubectl
  getVersions
  if [ "${HP_SM_PLATFORM_CORE}"  == "yes" ]; then
    logError "262" "Helix Platform CORE deployment - no tenant services deployed." 1
  fi
  if [ "${TCTL_CMD}" == "config" ]; then
    genTctlConfig
    exit
  fi
  deleteTCTLJob
  deployTCTL "${TCTL_CMD}"
  logMessage "tctl output is...\n"
  getTCTLOutput full
  echo "${TCTL_OUTPUT}"
  deleteTCTLJob
  exit
fi

# Print Jenkins credentials and exit
if [[ ! -z "${DUMP_JCREDS}" ]]; then
  logStatus "Jenkins credentials..."
  checkJenkinsIsRunning 1
  validateJenkinsCredentials
  logStatus "Pipeline passwords:"
  getPipelinePasswords | ${JQ_BIN} -r 'to_entries | sort_by(.key)[] | "        \u001b[32m\(.key)\u001b[0m / \u001b[31m\(.value.plainText)\u001b[0m"'
  exit
fi

if [ "${MODE}" == "jenkins" ]; then
  logStatus "Running Jenkins config checks only..."
  checkToolVersion kubectl
  getVersions
  checkJenkinsIsRunning 1
  UBER_VERSION=$(getPipelineParameterDefault HELIX_ONPREM_DEPLOYMENT PLATFORM_HELM_VERSION)
  checkCDE
  checkJenkinsConfig
  checkDERequirements
  tidyUp
  exit
fi

if [[ ! -z "${BUNDLE_ID}" ]]; then
  logStatus "Running IS deployment status check for bundle ID=${BUNDLE_ID}..."
  getDomain
  buildISAliasesArray
  getISAdminCreds
  getISJWT
  ${CURL_BIN} -sk -X GET "https://${IS_ALIAS_PREFIX}-restapi.${CLUSTER_DOMAIN}/api/rx/application/bundle/deploymentstatus/${BUNDLE_ID}" -H "Authorization: AR-JWT ${ARJWT}" | ${JQ_BIN} .
  exit
fi

if [ "${MODE}" == "fix" ]; then
  # Parse FIXOPTS to array
  read -r -a FIXARGS <<< "${FIXOPTS}"
  logStatus "Running HITT in fix mode '${FIXARGS[0]}'..."
  case "${FIXARGS[0]}" in
    cacerts)
      fixCacerts
      ;;
    addcert)
      fixAddCert
      ;;
    sat)
      fixSATRole
      ;;
    realm)
      fixSSORealm
      ;;
    jenkins)
      if [ ${#FIXARGS[@]} -eq 1 ]; then
        logError "999" "Usage: bash $0 -f \"jenkins fixtype [fixoptions]\"" 1
      fi
      fixJenkins
      ;;
    ssh)
      fixSSH "${GIT_USER}"
      ;;
    arlicense)
      if [ ${#FIXARGS[@]} -eq 1 ]; then
        logError "999" "Usage: bash $0 -f \"arlicense key [expiry]\"" 1
      fi
      applyARLicense
      ;;
    activatehp)
      activateHP
      ;;
    resetssopwd)
      resetSSOPasswd
      ;;
    help)
      showFixHelp
      ;;
    *)
      logError "999" "'${FIXARGS[0]}' is not a valid fix mode option." 1
      ;;
  esac
  exit
fi

if [ "${MODE}" == "getlog" ]; then
  if [ "${PIPELINE_NAME}" == "msgs" ]; then
    echo "${ALL_MSGS_JSON}"
    exit
  fi
  if [ "${PIPELINE_NAME}" == "help" ]; then
    showConsoleLogHelp
    exit
  fi
  checkJenkinsIsRunning 1
  case "${PIPELINE_NAME}" in
    jenkins)
      getJenkinsSystemLog
      exit
      ;;
    agent)
      getJenkinsAgentLog
      exit
      ;;
    *)
      getPipelineConsoleOutput "${PIPELINE_NAME}"
      exit
      ;;
  esac
fi

if [ "${MODE}" == "pipeline" ]; then
  read -r -a PIPELINEARGS <<< "${PIPELINEOPTS}"
  if [ "${PIPELINEARGS[0]}" == "help" ]; then
    showPipelineHelp
    exit
  fi
  logStatus "Running HITT in pipeline mode '${PIPELINEARGS[0]}'..."
  checkJenkinsIsRunning 1
  case "${PIPELINEARGS[0]}" in
    build)
      buildJenkinsPipelineFromFile
      ;;
    delete)
      if [ ${#PIPELINEARGS[@]} -lt 2 ]; then
        logError "999" "Usage: bash $0 -k \"delete BUILD_NUM|START-END [JOB_NAME]\"" 1
      fi
      deleteJenkinsJobs "${PIPELINEARGS[1]}" "${PIPELINEARGS[2]:-}"
      ;;
    get)
      getJenkinsPipelineValues
      ;;
    kickstart)
      kickstartGatherPlatformContext
      kickStartUberPipeline
      ;;
    *)
    logError "999" "'${PIPELINEARGS[0]}' is not a valid pipeline mode option (try: get, build, kickstart, delete, help)." 1
    ;;
  esac
  exit
fi

if [ "${MODE}" == "utility" ]; then
  # Parse UTILOPTS to array
  read -r -a UTILARGS <<< "${UTILOPTS}"
  logStatus "Running HITT in utility mode '${UTILARGS[0]}'..."
  case "${UTILARGS[0]}" in
    checkrbac|authcheck)
      if [[ "${UTILARGS[0]}" == "authcheck" ]]; then
        logMessage "Note: 'authcheck' is deprecated — use 'checkrbac hitt'." 1
      fi
      profile="${UTILARGS[1]:-hitt}"
      case "${profile}" in
        hitt|deploy|all)
          validateHittK8sPermissions "${profile}" || exit 1
          ;;
        *)
          logError "999" "Usage: bash $0 -u \"checkrbac [hitt|deploy|all]\" (default: hitt)." 1
          ;;
      esac
      ;;
    get)
      parseUtilGet
      ;;
    gendbid)
      if [ ${#UTILARGS[@]} -ne 4 ]; then
        logError "999" "Usage: bash $0 -u \"gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME\"" 1
      fi
      IS_DB_TYPE="${UTILARGS[1]}"
      IS_DATABASE_HOST_NAME="${UTILARGS[2]}"
      IS_AR_DB_NAME="${UTILARGS[3]}"
      generateISDbID
      ;;
    imagels)
      # 1 image
      # 2 dtr host/path optional
      if [[ "${UTILARGS[1]}" =~ / ]]; then
        SKOPEO_IMAGE="${UTILARGS[1]}"
      else
        SKOPEO_IMAGE="docker.io/bmchelix/${UTILARGS[1]}"
      fi
      listImageTags
      ;;
    sql)
      parseUtilSQL
      ;;
    checkpat)
      # USERNAME and PAT optional — offers bmc-dtrhub credentials from HP_NAMESPACE, then prompts
      validateDockerIOPat "${UTILARGS[1]:-}" "${UTILARGS[2]:-}"
      ;;
    help)
      showUtilHelp
      ;;
    *)
      logError "999" "'${UTILARGS[0]}' is not a valid utility mode option." 1
      ;;
  esac
  exit
fi

if [ "${MODE}" == "info" ]; then
  checkToolVersion kubectl
  logStatus "Running in info mode..."
  case "${MODEARGS[1]}" in
    cluster)
      QUIET=1
      logStatus "Gathering cluster information..." 1
      getK8sNodeDetails
      hittInfoPrintKv "Kubernetes version" "${K8S_VERSION:-unknown}"
      hittInfoPrintKv "OpenShift version" "${OPENSHIFT_VERSION:-n/a}"
      hittInfoPrintSection "Node summary"
      printK8sNodeDetails
      if [[ -n "${K8S_OOM_PODS_TABLE}" ]] && [[ $(printf '%s' "${K8S_OOM_PODS_TABLE}" | awk 'NF' | wc -l) -ge 2 ]]; then
        echo ""
        hittInfoPrintSection "OOM-killed pods"
        printK8sOomPods
      fi
      ;;
    helix)
      enumerateHelixVersions
      ;;
    ingress)
      QUIET=1
      logStatus "Gathering ingress information..." 1
      if checkK8sAuth get ingressclasses; then
        INGRESS_CLASSES=$(${KUBECTL_BIN} get ingressclasses)
        HP_INGRESS_CLASS=$(${KUBECTL_BIN} -n "${HP_NAMESPACE}" get ingress helixingress-master -o jsonpath='{.spec.ingressClassName}')
        discoverIngressControllerDetails "${HP_INGRESS_CLASS}"
      fi
      hittInfoPrintSection "Ingress controller"
      printIngressControllerDetails
      ;;
    full)
      gatherInfo
      printInfo
      writeInfoJson || true
      ;;
    help)
      showInfoHelp
      ;;
    *)
      logError "999" "'${MODEARGS[1]}' is not a valid info mode option (try: cluster, helix, ingress, full, help)." 1
      ;;
  esac
  exit
fi

# Validate action
[[ "${MODE}" =~ ^pre-hp|^post-hp$|^pre-is$|^post-is$ ]] || usage

# MODE is required
if [[ -z ${MODE} ]]; then
  logError "200" "Mode must be specified with -m <post-hp|pre-is|post-is>" 1
fi

if [ "${MODE}" == "post-hp" ] || [ "${MODE}" == "pre-hp" ]; then
  SKIP_JENKINS=1
fi

# Check required variables are settings
checkVars
logStatus "${BOLD}Starting HITT in ${MODE} mode...${NORMAL}"

# Check command line tools present
logStatus "Checking for required tools in path..."
checkRequiredTools
if [ "$(whoami)" == "root" ] && ! isJenkinsInCluster; then
  echo
  logWarning "035" "The HITT script should be run as the git user, not as root."
fi
logStatus "Checking cluster and namespaces..."
if [ "${HP_NAMESPACE}" == "${IS_NAMESPACE}" ]; then
  logError "201" "It is recommended to install the Helix Platform and Helix IS in their own namespaces."
fi
logMessage "Gathering cluster information..."
logK8sNodeDetails
logMessage "Gathering Helix Platform namespace information..."
checkHPNamespace "${HP_NAMESPACE}"
logPods ${HP_NAMESPACE}
logEvents ${HP_NAMESPACE}
if [ "${MODE}" != "post-hp" ]; then
  logMessage "Gathering Helix IS namespace information..."
  checkISNamespace "${IS_NAMESPACE}"
  logPods ${IS_NAMESPACE}
  logEvents ${IS_NAMESPACE}
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
logStatus "Checking Helix Platform certificates..."
validateCacertsFile HP

if [ "${MODE}" != "post-hp" ]; then
  logStatus "Checking Jenkins is accessible..."
  checkJenkinsIsRunning
  logStatus "Checking Jenkins configuration..."
  UBER_VERSION=$(getPipelineParameterDefault HELIX_ONPREM_DEPLOYMENT PLATFORM_HELM_VERSION)
  checkCDE
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
  validateCacertsFile IS
  logStatus "Checking IS Configuration..."
  checkISRESTReady
  checkISLicenseStatus
  checkISTenant
fi

logLBCertDetails

if [ "${MODE}" == "pre-is" ]; then
  logStatus "Checking Deployment Engine setup..."
  checkDERequirements
fi

if [ "${SKIP_JENKINS}" == "0" ]; then
  logStatus "Checking IS FTS Elastic settings..."
  checkFTSElasticSettings
  logStatus "Checking IS DB settings..."
  checkISDBSettings
  checkISDBLatency
  generateISDbID
fi

if [ "${MODE}" == "post-is" ]; then
  logPlatformFTSStartTime
  logStatus "Checking Helix IS platform-admin-ext service..."
  checkPlatformAdminExtSvc
  logStatus "Checking Support Assistant Tool..."
  checkAssistTool
fi

tidyUp

} # END of main()

# START
# Set vars and process command line
# UTC calendar build id (YYYYMMDD-NN, NN 01-99); incremented on each git commit via .githooks/pre-commit.
HITT_BUILD_VERSION="20260723-03"
: "${HITT_CONFIG_FILE=hitt.conf}"
HITT_URL=https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh
SHORT_HOSTNAME=$(hostname --short 2>/dev/null || hostname)
LONG_HOSTNAME=$(hostname --long 2>/dev/null || hostname)
GIT_USER=$(whoami)
: "${DEBUG=0}"
FAIL=0
WARN=0
SKIP_JENKINS=0
CREATE_LOGS=1
LOG_PASSWDS=0
HITT_LOG_FILE=hitt.log
HITT_DBG_FILE=hittdebug.log
HITT_ERR_FILE=hitterror.log
HITT_MSG_FILE=hittmsgs.log
VALUES_LOG_FILE=values.log
VALUES_JSON_FILE=values.json
CLEANUP_DIRS=(configsrepo itsmrepo)
CLEANUP_FILES=(is-sealcacerts hp-sealcacerts sealstore.p12 sealstore.pem kubeconfig.jenkins .cookies)
CLEANUP_START_FILES=("${HITT_MSG_FILE}" "${HITT_DBG_FILE}" "${HITT_ERR_FILE}" "${VALUES_LOG_FILE}" "${VALUES_JSON_FILE}" "jenkins-pipeline-build-response.log")
CLEANUP_STOP_FILES=()
REQUIRED_TOOLS=(kubectl curl keytool openssl jq base64 git java tar host zip unzip)
IS_ALIAS_SUFFIXES=(smartit sr is restapi atws dwp dwpcatalog vchat chat int reporting)
JENKINS_CREDS=(git github ansible_host ansible kubeconfig TOKENS password_vault_apikey)
IS_ALIAS_ARRAY=()
ADE_ALIAS_ARRAY=()
NAMESPACE_OTHER_OPTION="Other"
VERBOSITY=0
: "${QUIET=0}"
: "${SKIP_UPDATE_CHECK=0}"
: "${DISABLE_PROXY=0}"
BOLD=$'\e[1m'
NORMAL=$'\e[0m'
RED=$'\e[31m'
YELLOW=$'\e[33m'
GREEN=$'\e[32m'
SEALTCTL=sealtctl
# tmp set as used before processing config on initial setup
KUBECTL_BIN=kubectl
CURL_BIN=curl
JQ_BIN=jq
ERROR_ARRAY=()
WARN_ARRAY=()
JENKINS_CREDENTIALS=""
OPENSHIFT=0
SSLPOKE_PAYLOAD="
yv66vgAAADcA+AoARQBWCQBXAFgHAFkKAFoAWxIAAABfCgBgAGEIAGIIAGMKAFcAZAoAZQBmCgAM
AGcHAGgIAGkKAFcAaggAawkAVwBsEgABAG4HAG8KABIAcAoAAwBxCgAMAHIHAHMKAAwAdAcAdQoA
GABWCAB2CgAYAHcKABYAeAoAFgB5CgAWAHoKAFAAewoATwB8CgBPAH0KAGAAfggAfwcAgAoAJACB
CgASAHoIAIISAAIAXwgAhBIAAwCGCACHCACIEgAEAIYKAIoAiwgAjAoATgCNCgCOAI8SAAUAXxIA
BgBfCACSEgAHAJQKAFAAlQoAUACWCgASAHkHAJcHAJgKADoAmQoAOQCaCgA5AJsKAE4AnAgAnQoA
TgCeCACfBwCgEgAIAKIKAEIAowcApAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVy
VGFibGUBAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEADVN0YWNrTWFwVGFibGUHAKUH
AKYHAKcHAKgBABVvcGVuSHR0cENvbm5lY3RUdW5uZWwBADooTGphdmEvbmV0L1NvY2tldDtMamF2
YS9sYW5nL1N0cmluZztJTGphdmEvbGFuZy9TdHJpbmc7SSlWAQAKRXhjZXB0aW9ucwEAClNvdXJj
ZUZpbGUBAAxTU0xQb2tlLmphdmEMAEYARwcAqQwAqgCrAQAHU1NMUG9rZQcArAwArQCuAQAQQm9v
dHN0cmFwTWV0aG9kcw8GAK8IALAMALEAsgcAswwAtAC1AQBLVXNlIHByb3h5IHdpdGg6IC1EaHR0
cHMucHJveHlIb3N0PTxwcm94eUhvc3Q+IC1EaHR0cHMucHJveHlQb3J0PTxwcm94eVBvcnQ+AQBc
VXNlIHByb3h5IGF1dGhlbnRpY2F0aW9uIHdpdGg6IC1EaHR0cHMucHJveHlVc2VyPTx1c2VybmFt
ZT4gLURodHRwcy5wcm94eVBhc3N3b3JkPTxwYXNzd29yZD4MALYAtwcAuAwAuQC6DAC7ALwBAB5q
YXZheC9uZXQvc3NsL1NTTFNvY2tldEZhY3RvcnkBAA9odHRwcy5wcm94eUhvc3QMAL0AsgEAD2h0
dHBzLnByb3h5UG9ydAwAvgCrCAC/DACxAMABAA9qYXZhL25ldC9Tb2NrZXQMAEYAwQwAUQBSDADC
AMMBABdqYXZheC9uZXQvc3NsL1NTTFNvY2tldAwAwgDEAQAbamF2YXgvbmV0L3NzbC9TU0xQYXJh
bWV0ZXJzAQAFSFRUUFMMAMUAtQwAxgDHDADIAMkMAMoAywwAzAC3DADNAM4MAM8AzgwA0AC3AQAW
U3VjY2Vzc2Z1bGx5IGNvbm5lY3RlZAEAE2phdmEvbGFuZy9FeGNlcHRpb24MANEARwEADGphdmEu
dmVyc2lvbggA0gEACmh0dHAuYWdlbnQIANMMALEA1AEAD2h0dHBzLnByb3h5VXNlcgEAE2h0dHBz
LnByb3h5UGFzc3dvcmQIANUHANYMANcA2gEACklTTy04ODU5LTEMANsA3AcA3QwA3gDfCADgCADh
AQAACADiDACxAOMMAMwA5AwA5QBHAQAWamF2YS9pby9CdWZmZXJlZFJlYWRlcgEAGWphdmEvaW8v
SW5wdXRTdHJlYW1SZWFkZXIMAEYA5gwARgDnDADoAK4MAOkA6gEADEhUVFAvMS4xIDIwMAwA6wDs
AQAMSFRUUC8xLjAgMjAwAQATamF2YS9pby9JT0V4Y2VwdGlvbggA7QwAsQDuDABGALUBABBqYXZh
L2xhbmcvT2JqZWN0AQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TdHJpbmcBABNq
YXZhL2lvL0lucHV0U3RyZWFtAQAUamF2YS9pby9PdXRwdXRTdHJlYW0BABBqYXZhL2xhbmcvU3lz
dGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQAPamF2YS9sYW5nL0NsYXNzAQAHZ2V0
TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7CgDvAPABABZVc2FnZTogASA8aG9zdD4gPHBvcnQ+
AQAXbWFrZUNvbmNhdFdpdGhDb25zdGFudHMBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xh
bmcvU3RyaW5nOwEAE2phdmEvaW8vUHJpbnRTdHJlYW0BAAdwcmludGxuAQAVKExqYXZhL2xhbmcv
U3RyaW5nOylWAQAEZXhpdAEABChJKVYBABFqYXZhL2xhbmcvSW50ZWdlcgEACHBhcnNlSW50AQAV
KExqYXZhL2xhbmcvU3RyaW5nOylJAQAKZ2V0RGVmYXVsdAEAGygpTGphdmF4L25ldC9Tb2NrZXRG
YWN0b3J5OwEAC2dldFByb3BlcnR5AQADZXJyAQAQVXNpbmcgcHJveHk6IAE6AQEAJyhMamF2YS9s
YW5nL1N0cmluZztJKUxqYXZhL2xhbmcvU3RyaW5nOwEAFihMamF2YS9sYW5nL1N0cmluZztJKVYB
AAxjcmVhdGVTb2NrZXQBADgoTGphdmEvbmV0L1NvY2tldDtMamF2YS9sYW5nL1N0cmluZztJWilM
amF2YS9uZXQvU29ja2V0OwEAJihMamF2YS9sYW5nL1N0cmluZztJKUxqYXZhL25ldC9Tb2NrZXQ7
AQAic2V0RW5kcG9pbnRJZGVudGlmaWNhdGlvbkFsZ29yaXRobQEAEHNldFNTTFBhcmFtZXRlcnMB
ACAoTGphdmF4L25ldC9zc2wvU1NMUGFyYW1ldGVyczspVgEADmdldElucHV0U3RyZWFtAQAXKClM
amF2YS9pby9JbnB1dFN0cmVhbTsBAA9nZXRPdXRwdXRTdHJlYW0BABgoKUxqYXZhL2lvL091dHB1
dFN0cmVhbTsBAAV3cml0ZQEACWF2YWlsYWJsZQEAAygpSQEABHJlYWQBAAVwcmludAEAD3ByaW50
U3RhY2tUcmFjZQEABkphdmEvAQEAAwEgAQEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5n
L1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQADAToBAQAQamF2YS91dGlsL0Jhc2U2NAEACmdl
dEVuY29kZXIBAAdFbmNvZGVyAQAMSW5uZXJDbGFzc2VzAQAcKClMamF2YS91dGlsL0Jhc2U2NCRF
bmNvZGVyOwEACGdldEJ5dGVzAQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgEAGGphdmEvdXRpbC9C
YXNlNjQkRW5jb2RlcgEADmVuY29kZVRvU3RyaW5nAQAWKFtCKUxqYXZhL2xhbmcvU3RyaW5nOwEA
B0Jhc2ljIAEBABhQcm94eS1BdXRob3JpemF0aW9uOiABDQoBAChDT05ORUNUIAE6ASBIVFRQLzEu
MQ0KVXNlci1BZ2VudDogAQ0KAQ0KAQBLKExqYXZhL2xhbmcvU3RyaW5nO0lMamF2YS9sYW5nL1N0
cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAFKFtCKVYBAAVmbHVz
aAEAKihMamF2YS9pby9JbnB1dFN0cmVhbTtMamF2YS9sYW5nL1N0cmluZzspVgEAEyhMamF2YS9p
by9SZWFkZXI7KVYBAAhyZWFkTGluZQEAB2lzRW1wdHkBAAMoKVoBAApzdGFydHNXaXRoAQAVKExq
YXZhL2xhbmcvU3RyaW5nOylaAQAxVW5hYmxlIHRvIHR1bm5lbCB0aHJvdWdoIAE6AS4gUHJveHkg
cmVzcG9uc2U6ICIBIgEAOShMamF2YS9sYW5nL1N0cmluZztJTGphdmEvbGFuZy9TdHJpbmc7KUxq
YXZhL2xhbmcvU3RyaW5nOwcA8QwAsQD0AQAkamF2YS9sYW5nL2ludm9rZS9TdHJpbmdDb25jYXRG
YWN0b3J5BwD2AQAGTG9va3VwAQCYKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9v
a3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEv
bGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL2ludm9rZS9DYWxsU2l0
ZTsHAPcBACVqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwAQAeamF2YS9sYW5n
L2ludm9rZS9NZXRob2RIYW5kbGVzACEAAwBFAAAAAAADAAEARgBHAAEASAAAAB0AAQABAAAABSq3
AAGxAAAAAQBJAAAABgABAAAAEAAJAEoASwABAEgAAAHtAAUACwAAAPUqvgWfACeyAAISA7YABLoA
BQAAtgAGsgACEge2AAayAAISCLYABgS4AAkqAzJMKgQyuAAKPbgAC8AADDoEEg24AA46BRIPuAAO
OgYDNgcZBcYARxkGxgBCGQa4AAo2B7IAEBkFFQe6ABEAALYABrsAElkZBRUHtwATOggZCBkFFQcr
HLgAFBkEGQgrHAS2ABXAABZOpwAOGQQrHLYAF8AAFk67ABhZtwAZOggZCBIatgAbLRkItgAcLbYA
HToJLbYAHjoKGQoEtgAfGQm2ACCeABGyAAIZCbYAIbYAIqf/7bIAAhIjtgAGpwAMTCu2ACUEuAAJ
sQABACoA6ADrACQAAgBJAAAAhgAhAAAAEgAGABMAFgAUAB4AFQAmABYAKgAZAC4AGgA1ABwAPQAd
AEQAHgBLAB8ATgAgAFgAIQBfACIAbgAjAHsAJACGACUAlAAmAJcAJwCiACkAqwAqALIAKwC4ACwA
vgAtAMQALgDKAC8A0gAwAOAAMgDoADYA6wAzAOwANADwADUA9AA3AEwAAABSAAcq/wBsAAgHAE0H
AE4BAAcADAcATgcATgEAAP8ACgAIBwBNBwBOAQcAFgcADAcATgcATgEAAP4AJwcAGAcATwcAUBX/
AAoAAQcATQABBwAkCAAKAFEAUgACAEgAAAJWAAYAEAAAAPYqtgAmOgUSJ7gADroAKAAAOgYSKbgA
DscACBkGpwAPEim4AA4ZBroAKgAAOgcSK7gADjoIEiy4AA46CQE6ChkIxgAnGQnGACIZCBkJugAt
AAA6C7gALhkLEi+2ADC2ADG6ADIAADoKLRUEGQcZCsYADRkKugAzAACnAAUSNLoANQAAOgsZBRkL
Ei+2ADC2ADYZBbYANyq2ADg6DLsAOVm7ADpZGQwSL7cAO7cAPDoNAzYPGQ22AD1ZOg7GACUZDrYA
PpoAHRkOEj+2AECaAA0ZDhJBtgBAmf/cBDYPp//WFQ+aABS7AEJZKxwZDroAQwAAtwBEv7EAAAAC
AEkAAABaABYAAAA6AAYAOwASADwALQA9ADQAPgA7AD8APgBAAEgAQQBTAEIAZwBEAGwARgCEAEgA
kABJAJUASgCbAEsArwBNALIATgDFAE8A2QBQAN8AUwDkAFQA9QBWAEwAAADuAAn9AB8HAFAHAE5L
BwBO/wA7AAsHABIHAE4BBwBOAQcAUAcATgcATgcATgcATgcATgAA/wATAAsHABIHAE4BBwBOAQcA
UAcATgcATgcATgcATgcATgADBwBOAQcATv8AAQALBwASBwBOAQcATgEHAFAHAE4HAE4HAE4HAE4H
AE4ABAcATgEHAE4HAE7/ADQAEAcAEgcATgEHAE4BBwBQBwBOBwBOBwBOBwBOBwBOBwBOBwBPBwA5
AAEAAP8AJgAQBwASBwBOAQcATgEHAFAHAE4HAE4HAE4HAE4HAE4HAE4HAE8HADkHAE4BAAAFFQBT
AAAABAABAEIAAwBUAAAAAgBVANkAAAASAAIAjgCKANgACQDyAPUA8wAZAFwAAAA4AAkAXQABAF4A
XQABAG0AXQABAIMAXQABAIUAXQABAIkAXQABAJAAXQABAJEAXQABAJMAXQABAKE="
#MSG_PAYLOAD=""
#ALL_MSGS_JSON=$(echo "${MSG_PAYLOAD}" | ${BASE64_BIN} -d | zcat 2>/dev/null)
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
    \"remediation\": \"If the alias has been removed after the Jenkins HELIX_ITSM_INTEROPS pipeline has been run, add the portal FQDN to the Applications Domain in the Helix Service Management SSO realm.\"
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
    \"remediation\": \"Use the steps in the 'Performing the post-installation configurations' documentation to add an externalIP to the service.\"
  },
  {
    \"id\": \"026\",
    \"cause\": \"The platform-admin-ext service is not one of the expected types of ClusterIP or NodePort.\",
    \"impact\": \"Connectivity via the service for AR API clients such as Developer Studio may not be possible and upgrades may fail.\",
    \"remediation\": \"Review the platform-admin-ext service configuration in the cluster and revert any customisations.\"
  },
  {
    \"id\": \"027\",
    \"cause\": \"The DATABASE_HOST_NAME is not reachable from this system on the DB_PORT.\",
    \"impact\": \"Later checks to validate the database will not be run and deployment will fail if either of the values are wrong.\",
    \"remediation\": \"This is expected if there is no connectivity to the database server from this system, otherwise verify the DATABASE_HOST_NAME/DB_PORT values.\"
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
    \"cause\": \"HITT 'pre-is' mode is used to validate the environment and HELIX_ONPREM_DEPLOYMENT pipeline values before deployment but the pipeline operation is not the expected value of 'FRESH'.\",
    \"impact\": \"HITT checks may return incorrect results.\",
    \"remediation\": \"Confirm the pipeline operation is correct and review any warnings/errors carefully as the results may be unreliable.\"
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
    \"id\": \"035\",
    \"cause\": \"The HITT script is being run by the root user.\",
    \"impact\": \"Some HITT checks may fail as they are expected to be run by the git user.\",
    \"remediation\": \"Run the HITT script as the git user.\"
  },
  {
    \"id\": \"036\",
    \"cause\": \"The 'ansible-galaxy' command was not found but this is required to check that the community.general collection is installed.\",
    \"impact\": \"If the collection is not installed deployment will fail.\",
    \"remediation\": \"Install the 'ansible-galaxy' command to enable the checks or ensure that the community.general collection is installed.\"
  },
  {
    \"id\": \"037\",
    \"cause\": \"The Helix Portal alias is present in the Helix Service Management RSSO realm. This alias is added during the Jenkins HELIX_ITSM_INTEROPS pipeline run.\",
    \"impact\": \"The alias is not expected to be present until the Jenkins HELIX_ITSM_INTEROPS pipeline is run.\",
    \"remediation\": \"If the Jenkins HELIX_ITSM_INTEROPS pipeline has not been run, remove the portal alias from the Applications Domains in the Helix Service Management SSO realm.\"
  },
  {
    \"id\": \"038\",
    \"cause\": \"The Linux 'ssphass' command was not found.\",
    \"impact\": \"The password value set in the Jenkins credentials will not be validated.\",
    \"remediation\": \"Please install 'sshpass' or make sure it is on the path of the user running the HITT script.\"
  },
  {
    \"id\": \"039\",
    \"cause\": \"The Linux 'ssh-keygen' command was not found.\",
    \"impact\": \"Checks to test that passwordless ssh is set up correctly will not be run.\",
    \"remediation\": \"Please install 'ssh-keygen' or make sure it is on the path of the user running the HITT script.\"
  },
  {
    \"id\": \"040\",
    \"cause\": \"This is a FRESH deployment using Postgres and the option to allow the pipeline to restore the databas dump is not selected.\",
    \"impact\": \"The database dump must be restored manually before deployment if the DATABASE_RESTORE option is not selected.\",
    \"remediation\": \"Ensure that the database dump has been restored OR select the DATABASE_RESTORE option to allow the pipeline to do it.\"
  },
  {
    \"id\": \"041\",
    \"cause\": \"The named Helix Platform tenant has not been activated.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline may encounter issues.\",
    \"remediation\": \"Use the link in the activation email or login to set the first user password and activate the tenant.\"
  },
  {
    \"id\": \"042\",
    \"cause\": \"The OS_RESTRICTED_SCC option is not selected but the cluster type is OpenShift.\",
    \"impact\": \"Pods will may be blocked from starting and deployment will fail.\",
    \"remediation\": \"Check if the cluster uses restricted SCCs and select the option if required.\"
  },
  {
    \"id\": \"043\",
    \"cause\": \"The named alias is not accessible from this system using a curl command.\",
    \"impact\": \"Deployment may fail as some aliases, RESTAPI for example, are used by the pipeline scripts.\",
    \"remediation\": \"Make sure the aliases are correctly set up and accessible - check firewall settings etc.\"
  },
  {
    \"id\": \"044\",
    \"cause\": \"The platform-fts pod took longer than expected to become ready.\",
    \"impact\": \"This may indicate poor latency between the pod and the IS database system or some other performance issue.\",
    \"remediation\": \"Check the db latency or contact BMC Support if you observe performance related issues.\"
  },
    {
    \"id\": \"045\",
    \"cause\": \"'PasswordAuthentication no' appears to be set in the /etc/ssh/sshd_config file.\",
    \"impact\": \"Checks to validate the git user password set in Jenkins credentials cannot be run and pipelines may fail.\",
    \"remediation\": \"Check the /etc/ssh/sshd_config file and comment out 'PasswordAuthentication no' or set the value to yes.\"
  },
    {
    \"id\": \"046\",
    \"cause\": \"The cacerts file for the named application was not found.\",
    \"impact\": \"Checks to validate the certificates have not been run and deployment failures or application issues may result.\",
    \"remediation\": \"Provide the required certificates as detailed in the product documentation.\"
  },
  {
    \"id\": \"047\",
    \"cause\": \"DB_JDBC_URL is set which requires port 6200 on the DB server to be accessible if using RAC.\",
    \"impact\": \"Platform pods will not start.\",
    \"remediation\": \"Make sure the ONS port (6200) is open for connections from Kubernetes.\"
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
    \"impact\": \"Some checks will not be run and HITT results will be imcomplete.\",
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
    \"cause\": \"The required ITSM services are not installed in the Helix Platform, likely because of an invalid setting in the deployment.config.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Rerun the Helix Platform deployment-manager.sh script with the setting named in the error set to yes to install the missing services.\"
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
    \"cause\": \"The value of the named parameter in the HELIX_ONPREM_DEPLOYMENT pipeline is not a context in the kubeconfig file.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Update the value to the correct context. Use 'kubectl config get-contexts' to list valid options.\"
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
    \"cause\": \"The value of the named parameter in the HELIX_ONPREM_DEPLOYMENT pipeline is different to the DOMAIN used for the Helix Platform.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"Helix Service Management and Helix Platform are expected to use the same domain. Correct the value in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
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
    \"cause\": \"The named cacerts object required by the Helix applications is missing.\",
    \"impact\": \"Helix applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts object using the process detailed in the product documentation.\"
  },
  {
    \"id\": \"160\",
    \"cause\": \"The named cacerts object does not contain the Java keystore in a file named 'cacerts'.\",
    \"impact\": \"Helix applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts object using the process detailed in the product documentation and ensure that the Java keystore file is named 'cacerts'.\"
  },
  {
    \"id\": \"161\",
    \"cause\": \"The cacerts file in the named object must be a Java keystore and not any other type of certificate file.\",
    \"impact\": \"Helix applications will be inaccessible.\",
    \"remediation\": \"Recreate the cacerts object using the process detailed in the product documentation and ensure that the cacerts file is a Java keystore.\"
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
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be inaccessible.\",
    \"remediation\": \"Set the value to 9200.\"
  },
  {
    \"id\": \"174\",
    \"cause\": \"The FTS_ELASTICSEARCH_SECURE option must be selected.\",
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be inaccessible.\",
    \"remediation\": \"Select the value.\"
  },
  {
    \"id\": \"175\",
    \"cause\": \"The FTS_ELASTICSEARCH_USER_PASSWORD value does not match the value set in the Helix Platform.\",
    \"impact\": \"The Helix Service Management platform pods will not start and the applications will be inaccessible.\",
    \"remediation\": \"Set the value to the correct password.\"
  },
  {
    \"id\": \"176\",
    \"cause\": \"An attempt to login to the Helix Service Management apps via the RESTAPI failed.\",
    \"impact\": \"Some IS configuration checks will be skipped.\",
    \"remediation\": \"Check that the hannah_admin user is enabled and that the correct password is stored in the atriumwebsvc secret. If the password contains %, &, +, or other reserved form characters, use a current HITT build that URL-encodes the login request (curl --data-urlencode).\"
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
    \"cause\": \"Different versions of the Helix Service Management database are identified using the currDbVersion value in the control table. The discovered value is not the expected one for this version of Helix Service Management.\",
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
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Credentials and update the credential to add the missing password.\"
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
    \"impact\": \"Helix Service Management deployment may fail if the credentials are invalid.\",
    \"remediation\": \"Verify the credentials in the IMAGESECRET_NAME secret in the Helix Service Management namespace. This is expected if the registry server is not accessible from this system.\"
  },
  {
    \"id\": \"193\",
    \"cause\": \"The HELIX_ONPREM_DEPLOYMENT process uses several Jenkins nodes to perform product installation but one, or more, of these is not available.\",
    \"impact\": \"Helix Service Management deployment will fail.\",
    \"remediation\": \"In Jenkins go to Manage Jenkins -> Nodes and enable the offline node(s). This may indicate an ssh or git credentials password issue. See the product documentation for full details.\"
  },
  {
    \"id\": \"194\",
    \"cause\": \"There are no Jenkins nodes with the label named in the error message but one is required by the deployment pipelines.\",
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
    \"cause\": \"Unable to verify the file in the Jenkins KUBECONFIG credential. It is expected to contain a valid kubeconfig file but it is missing or is not valid for the cluster.\",
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
    \"cause\": \"The command to list namespaces in the cluster did not return the expected results needed to provide a list to select from.\",
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
    \"impact\": \"Helix Platform and Helix IS are not certified in the same namespace.\",
    \"remediation\": \"Use separate namespaces and update the hitt.conf file.\"
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
    \"cause\": \"This value should be the ID of a Jenkins credentials object containing the OS user/password used by the pipeline to access the git repository files.\",
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
    \"cause\": \"The pipeine is running an UPGRADE or UPDATE but the SOURCE_VERSION or PLATFORM_HELM_VERSION are invalid for the chosen mode.\",
    \"impact\": \"The UPGRADE/UPDATE will fail.\",
    \"remediation\": \"Review the product documentation and verify the SOURCE_VERSION and PLATFORM_HELM_VERSION values.\"
  },
  {
    \"id\": \"214\",
    \"cause\": \"The password entered for CACERTS_SSL_TRUSTSTORE_PASSWORD is not valid for the cacerts file attached to the pipeline or stored in the cacerts secret.\",
    \"impact\": \"Platform pods will be unable to start.\",
    \"remediation\": \"Set CACERTS_SSL_TRUSTSTORE_PASSWORD to the correct password or leave it blank to use the default.\"
  },
  {
    \"id\": \"215\",
    \"cause\": \"The named global pipeline libraries were not found in Jenkins.\",
    \"impact\": \"Pipeline execution will fail.\",
    \"remediation\": \"Add the missing libraries and ensure they are created as 'Global Trusted Pipeline Libraries' and not 'Global Untrusted Pipeline Libraries'.\"
  },
  {
    \"id\": \"216\",
    \"cause\": \"The command 'ansible --version' that is used to determine the Ansible version did not return results in the expected format.\",
    \"impact\": \"Some checks to validate ansible will not be run.\",
    \"remediation\": \"Review the output of the 'ansible --version' command and make sure that you are using a supported version.\"
  },
  {
    \"id\": \"217\",
    \"cause\": \"The DB_JDBC_URL parameter is set but this is only supported when DB_TYPE is oracle.\",
    \"impact\": \"The HELIX_SMARTAPPS_DEPLOY pipeline will fail at the catalog-data-upgrade stage.\",
    \"remediation\": \"Remove the value from the DB_JDBC_URL parameter.\"
  },
  {
    \"id\": \"218\",
    \"cause\": \"The named hostname alias was not found in the Helix certificate returned by the load balancer.\",
    \"impact\": \"Deployment may fail.\",
    \"remediation\": \"Check the Helix certificate and make sure that all required Helix hostname aliases are present as SAN entries, or use a wildcard.\"
  },
  {
    \"id\": \"219\",
    \"cause\": \"The hitt.conf file has a value set for the JENKINS_PASSWORD but the JENKINS_USERNAME value is blank.\",
    \"impact\": \"HITT cannot continue.\",
    \"remediation\": \"Please set, or clear, the JENKINS_PASSWORD and JENKINS_USERNAME values in the hitt.conf file.\"
  },
  {
    \"id\": \"220\",
    \"cause\": \"The CHECKOUT_USING_USER value must be set - the expected value is 'github'.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the CHECKOUT_USING_USER value to 'github'.\"
  },
  {
    \"id\": \"221\",
    \"cause\": \"The GIT_REPO_DIR value must be set using the expected format of 'ssh://<Jenkins server host name>/home/git/git_repo'.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the GIT_REPO_DIR to the correct value.\"
  },
  {
    \"id\": \"222\",
    \"cause\": \"The GIT_USER_HOME_DIR value is not a valid directory path.  Check the output of the command 'file <value of GIT_USER_HOME_DIR>'.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the GIT_USER_HOME_DIR to the correct value.\"
  },
  {
    \"id\": \"223\",
    \"cause\": \"The Helix Platform 24.4.00.001 hotfix has not been installed.\",
    \"impact\": \"Helix applications may become unavailable due to defects DRRE3-7571 & DRRE3-7638.\",
    \"remediation\": \"Review the product documentation and download and install the hotfix.\"
  },
  {
    \"id\": \"224\",
    \"cause\": \"The directory referenced in the GIT_REPO_DIR value is not accessible or does not exist.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Review the product documentation and set the correct value.\"
  },
  {
    \"id\": \"225\",
    \"cause\": \"The 'ansible-galaxy' community.general collection is not installed.\",
    \"impact\": \"If the collection is not installed deployment will fail.\",
    \"remediation\": \"Install the ansible community.general collection using the command 'ansible-galaxy collection install community.general'.\"
  },
  {
    \"id\": \"226\",
    \"cause\": \"The value of the GIT_REPO_DIR parameter should not have a forward slash as the last character.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Remove the trailing forward slash '/'.\"
  },
  {
    \"id\": \"227\",
    \"cause\": \"HITT was unable to create a file in the current directory.\",
    \"impact\": \"HITT cannot run.\",
    \"remediation\": \"Make sure you have permissions to create files in the current directory.\"
  },
  {
    \"id\": \"228\",
    \"cause\": \"HITT attempted to update the '.hitt.conf' file but it is not writable by the current user.\",
    \"impact\": \"HITT cannot run.\",
    \"remediation\": \"Delete the '.hitt.conf' file.\"
  },
  {
    \"id\": \"229\",
    \"cause\": \"The Helix Platform alias named in the message should not be present in the list of Application Domains of the SSO realm for ITSM aliases.\",
    \"impact\": \"Invalid configuration.\",
    \"remediation\": \"Delete the named alias from the SSO realm Application Domains.\"
  },
  {
    \"id\": \"230\",
    \"cause\": \"One or more of the Jenkins credentials have different passwords when they should all be set to the password of the git user.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Run 'bash hitt.sh -j' to display the passwords and then, in Jenkins go to Manage Jenkins->Credentials, and update those that have the wrong value.\"
  },
  {
    \"id\": \"231\",
    \"cause\": \"The password set for the git user in the Jenkins credentials is not correct. Run 'bash hitt.sh -j' to display the values.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Update the password for the ansible/ansible_host/github credentials in Jenkins and set it to that of the git user.\"
  },
  {
    \"id\": \"232\",
    \"cause\": \"The Tenant value in the RSSO realm for ITSM is null when it should be set to the Helix Platform tenant name.id.\",
    \"impact\": \"The HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Set the RSSO realm Tenant option to the correct value.\"
  },
  {
    \"id\": \"233\",
    \"cause\": \"The 'Remote Repository' value for the named global pipeline library is invalid - it should begin with 'ssh://<GIT_USER>@'.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Browse to Manage Jenkins -> System and update the pipeline library definition with the correct value as per the BMC docs.\"
  },
  {
    \"id\": \"234\",
    \"cause\": \"The directory in the 'Remote Repository' value for the named global pipeline library is invalid. Please make sure the path is correct.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Browse to Manage Jenkins -> System and update the pipeline library definition with the correct path to the .git directory.\"
  },
  {
    \"id\": \"235\",
    \"cause\": \"The ~/.ssh directory does not exist but is required for ssh connections.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Refer to the Helix Service Management product docs for steps to set up and configure ssh for the git and jenkins users.\"
  },
  {
    \"id\": \"236\",
    \"cause\": \"An attempt to use ssh to connect as git from a Jenkins script failed.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Make sure that the jenkins user can ssh to the git user without being prompted for a password or other inputs.\"
  },
  {
    \"id\": \"237\",
    \"cause\": \"Passwordless ssh for the git user is not set up correctly.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Make sure that the git user can ssh to the git user without being prompted for a password or other inputs.\"
  },
  {
    \"id\": \"238\",
    \"cause\": \"The script named in the message has not been approved.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Review the console output of the HELIX_ONPREM_DEPLOYMENT pipeline and look for the option to approve the missing script.\"
  },
  {
    \"id\": \"239\",
    \"cause\": \"One of the required command line tools is not installed or found on the path of the git user.\",
    \"impact\": \"Pipeline builds will fail.\",
    \"remediation\": \"Install the missing packages or make sure that they are available on the path of the git user.\"
  },
  {
    \"id\": \"240\",
    \"cause\": \"The value of the DB_PORT parameter must be the port number of the database but it is not in the expected format.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the DB_PORT value to the correct number.\"
  },
  {
    \"id\": \"241\",
    \"cause\": \"HELIX_FULL_STACK_UPGRADE is not selected but it is required when the pipeline operation is UPGRADE.\",
    \"impact\": \"The upgrade will fail.\",
    \"remediation\": \"Select the HELIX_FULL_STACK_UPGRADE option if you are upgrading.\"
  },
  {
    \"id\": \"242\",
    \"cause\": \"The HELIX_FULL_STACK_UPGRADE option should not be selected when the pipeline operation is UPDATE.\",
    \"impact\": \"The update will fail.\",
    \"remediation\": \"Deselect the HELIX_FULL_STACK_UPGRADE option when the pipeline operation is UPDATE.\"
  },
  {
    \"id\": \"243\",
    \"cause\": \"The IMAGESECRET_NAME pipeline parameter cannot be blank.\",
    \"impact\": \"The HELIX_GENERATE_CONFIG pipeline will fail.\",
    \"remediation\": \"Enter a value for the IMAGESECRET_NAME which will be used as the name of the registry credentials secret in the Helix Service Management namespace.\"
  },
  {
    \"id\": \"244\",
    \"cause\": \"The GIT_USER_HOME_DIR value must be a path name beginning with a forward slash.\",
    \"impact\": \"The HELIX_ONPREM_DEPLOYMENT pipeline will fail.\",
    \"remediation\": \"Change the GIT_USER_HOME_DIR value to an absolute path - for example '/home/git'.\"
  },
  {
    \"id\": \"245\",
    \"cause\": \"Either or both of the named pipeline parameters are blank.\",
    \"impact\": \"Deployment will fail and some HITT checks have been skipped.\",
    \"remediation\": \"Set the missing values in the HELIX_ONPREM_DEPLOYMENT pipeline.\"
  },
  {
    \"id\": \"246\",
    \"cause\": \"The 'Project Repository' value for the named Global Pipeline Library does not reference the expected .git directory.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the correct 'Project Repository' value for the named Global Pipeline Library.\"
  },
  {
    \"id\": \"247\",
    \"cause\": \"One or more of the SSH setup tests identified a permissions issue.\",
    \"impact\": \"Jenkins and the deployment pipelines will likely fail.\",
    \"remediation\": \"Review permissions on the files/directories noted in the error.\"
  },
  {
    \"id\": \"248\",
    \"cause\": \"There are one or more trailing spaces at the end of the named value.\",
    \"impact\": \"Deployment pipelines will fail.\",
    \"remediation\": \"Go to Manage Jenkins->System and remove the trailing spaces.\"
  },
  {
    \"id\": \"249\",
    \"cause\": \"One or more of the SSH setup tests identified a permissions issue.\",
    \"impact\": \"Jenkins and the deployment pipelines will likely fail.\",
    \"remediation\": \"Review permissions on the files/directories noted in the error.\"
  },
  {
    \"id\": \"250\",
    \"cause\": \"The value of the RSSO_ADMIN_PASSWORD does not match the Helix Platform RSSO password.\",
    \"impact\": \"HELIX_ONPREM_DEPLOYMENT pipeline will fail at the RSSO validation stage.\",
    \"remediation\": \"Update the RSSO_ADMIN_PASSWORD to the correct value.\"
  },
  {
    \"id\": \"251\",
    \"cause\": \"The cluster context value is present in the kubeconfig but failed to return values from the cluster.\",
    \"impact\": \"The HELIX_GENERATE_CONFIG pipeline will fail.\",
    \"remediation\": \"Validate the context and cluster permissions it has assigned.\"
  },
  {
    \"id\": \"252\",
    \"cause\": \"The IMAGESECRET_NAME value is set to the same name as a BMC provided secret.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Change the name you provided for IMAGESECRET_NAME.\"
  },
  {
    \"id\": \"253\",
    \"cause\": \"Jenkins and GITEA are running as containers so the CONTAINERIZED_DE must be selected.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Select the CONTAINERIZED_DE option.\"
  },
  {
    \"id\": \"254\",
    \"cause\": \"The CONTAINERIZED_DE option should only be selected when Jenkins/GITEA are running in containers.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Deselect the CONTAINERIZED_DE option.\"
  },
  {
    \"id\": \"255\",
    \"cause\": \"GIT_USER_HOME_DIR value must be '/home/jenkins' when Jenkins/GITEA are containerized.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the GIT_USER_HOME_DIR value to'/home/jenkins'.\"
  },
  {
    \"id\": \"256\",
    \"cause\": \"GIT_REPO_DIR value is not valie when Jenkins/GITEA are containerized.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Set the GIT_REPO_DIR value to suggested value.\"
  },
  {
    \"id\": \"257\",
    \"cause\": \"The custom_cacert.pem file used during the Helix Platform deployment does not appear to contain the certificates needed for the Service Management aliases.\",
    \"impact\": \"HELIX_ITSM_INTEROPS pipeline will fail.\",
    \"remediation\": \"Validate the custom_cacerts.pem and follow the docs to update the system.\"
  },
  {
    \"id\": \"258\",
    \"cause\": \"The value of the named parameter is not valid. It must consist of lower case alphanumeric characters or '-'.\",
    \"impact\": \"Deployment will fail.\",
    \"remediation\": \"Update the value to a valid string.\"
  },
  {
    \"id\": \"259\",
    \"cause\": \"The same pipeline library name is configured under both Global Trusted Libraries and Global Untrusted Libraries in Jenkins.\",
    \"impact\": \"Library resolution is ambiguous and may not match the intended trusted/untrusted behavior.\",
    \"remediation\": \"Remove the library from one of the two global lists so it is defined in only Global Trusted Libraries or only Global Untrusted Libraries.\"
  },
  {
    \"id\": \"260\",
    \"cause\": \"The same library name appears more than once under Global Trusted Libraries in Jenkins.\",
    \"impact\": \"Pipeline shared library configuration is invalid.\",
    \"remediation\": \"Edit Jenkins global configuration and delete duplicate Global Trusted Library entries with the same name.\"
  },
  {
    \"id\": \"261\",
    \"cause\": \"The same library name appears more than once under Global Untrusted Libraries in Jenkins.\",
    \"impact\": \"Pipeline shared library configuration is invalid.\",
    \"remediation\": \"Edit Jenkins global configuration and delete duplicate Global Untrusted Library entries with the same name.\"
  },
  {
    \"id\": \"262\",
    \"cause\": \"The Helix Platform is a CORE mode deployment with no tenant services.\",
    \"impact\": \"tctl commands are not applicable and will not work.\",
    \"remediation\": \"No Helix Platform tenant features are installed.\"
  },
  {
    \"id\": \"263\",
    \"cause\": \"CUSTOM_BINARY_PATH is selected but this is not supported when Jenkins is running in a pod.\",
    \"impact\": \"The HELIX_GENERATE_CONFIG pipeline will fail.\",
    \"remediation\": \"Deselect the CUSTOM_BINARY_PATH option.\"
  },
  {
    \"id\": \"264\",
    \"cause\": \"RSSO_URL value does not start with 'https://'.\",
    \"impact\": \"The HELIX_GENERATE_CONFIG pipeline will fail.\",
    \"remediation\": \"Update the value and add the missing prefix.\"
  }
]"

if [ ! -t 1 ]; then
  REDIRECT=1
fi

while getopts "b:c:C:dD:e:E:f:ghH:I:jJ:k:lm:o:pP:qs:t:u:U:vxz" options; do
  case "${options}" in
    b)
      BUNDLE_ID="${OPTARG}"
      SKIP_UPDATE_CHECK=1
      ;;
    c)
      HITT_CONFIG_FILE="${OPTARG}"
      ;;
    C)
      CONF_OVERRIDE=1
      IS_CUSTOMER_SERVICE_OVERRIDE="${OPTARG}"
      ;;
    d)
      DEBUG=1
      ;;
    D)
      CONF_OVERRIDE=1
      CDE_NAMESPACE_OVERRIDE="${OPTARG}"
      ;;
    e)
      STOP_ON_ERROR="${OPTARG}"
      MSG_LOOKUP_CANDIDATE=1
      ;;
    E)
      CONF_OVERRIDE=1
      IS_ENVIRONMENT_OVERRIDE="${OPTARG}"
      ;;
    f)
      SKIP_UPDATE_CHECK=1
      # Check if the next argument in the list is a "stray" (doesn't start with -)
      # ${!OPTIND} is a Bash feature that gets the value of the argument at that index
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "999" "When using FIX mode commands with options you must enclose them in double quotes - eg: bash $0 -f \"cacerts /path/to/new/cacerts-file\"" 1
      fi
      MODE=fix
      FIXOPTS="${OPTARG}"
      ;;
    g)
      IGNORE_ERRORS=1
      ;;
    h)
      SKIP_UPDATE_CHECK=1
      HELP_TOPIC=""
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        HELP_TOPIC="${NEXT_VAL}"
        ((OPTIND++))
      fi
      showHittHelp "${HELP_TOPIC}"
      exit 0
      ;;
    H)
      CONF_OVERRIDE=1
      HP_NAMESPACE_OVERRIDE="${OPTARG}"
      ;;
    I)
      CONF_OVERRIDE=1
      IS_NAMESPACE_OVERRIDE="${OPTARG}"
      ;;
    j)
      DUMP_JCREDS=1
      SKIP_UPDATE_CHECK=1
      ;;
    J)
      CONF_OVERRIDE=1
      JENKINS_URL_OVERRIDE="${OPTARG}"
      ;;
    k)
      SKIP_UPDATE_CHECK=1
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "999" "When using PIPELINE mode commands with options you must enclose them in double quotes - eg: bash $0 -k \"build filename\"" 1
      fi
      MODE=pipeline
      [[ -n "${REDIRECT}" ]] && QUIET=1
      PIPELINEOPTS="${OPTARG}"
      ;;
    l)
      CREATE_LOGS=0
      ;;
    m)
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "999" "When using mode (-m) commands with multiple words you must enclose them in double quotes - eg: bash $0 -m \"info ingress\"" 1
      fi
      # Parse UTILOPTS to array
      read -r -a MODEARGS <<< "${OPTARG}"
      MODE="${MODEARGS[0]}"
      if [ "${MODE}" == "info" ] && [ "${#MODEARGS[@]}" -eq 1 ]; then
        MODEARGS+=("full")
      fi
      ;;
    o)
      QUIET=1
      MODE=getlog
      SKIP_UPDATE_CHECK=1
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "999" "Usage: bash $0 -o <jenkins|agent|PIPELINE_NAME|help>" 1
      fi
      PIPELINE_NAME="${OPTARG}"
      ;;
    p)
      LOG_PASSWDS=1
      ;;
    P)
      CONF_OVERRIDE=1
      JENKINS_PASSWORD_OVERRIDE="${OPTARG}"
      ;;
    q)
      QUIET=1
      SKIP_UPDATE_CHECK=1
      ;;
    t)
      TCTL_CMD="${OPTARG}"
      SKIP_UPDATE_CHECK=1
      [[ -n "${REDIRECT}" ]] && QUIET=1
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "206" "tctl commands must be enclosed in double quotes - eg hitt.sh -t \"get tenant\"" 1
      fi
      ;;
    u)
      SKIP_UPDATE_CHECK=1
      [[ -n "${REDIRECT}" ]] && QUIET=1
      # Check if the next argument in the list is a "stray" (doesn't start with -)
      # ${!OPTIND} is a Bash feature that gets the value of the argument at that index
      NEXT_VAL="${!OPTIND}"
      if [[ -n "$NEXT_VAL" && "$NEXT_VAL" != -* ]]; then
        logError "999" "When using UTILITY mode commands with options you must enclose them in double quotes - eg: bash $0 -u \"command option\"" 1
      fi
      MODE=utility
      UTILOPTS="${OPTARG}"
      ;;
    U)
      CONF_OVERRIDE=1
      JENKINS_USERNAME_OVERRIDE="${OPTARG}"
      ;;
    v)
      VERBOSITY=1
      ;;
    x)
      DISABLE_PROXY=1
      ;;
    z)
      SKIP_CLEANUP=1
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

if [[ "${MSG_LOOKUP_CANDIDATE}" == "1" ]] && ! isHittActionRun; then
  showMessageById "${STOP_ON_ERROR}"
  exit 0
fi

# Call main()
if [ ${CREATE_LOGS} -eq 1 ]; then
  if [ "${DEBUG}" == "1" ]; then
    set -x
  fi
  main 2>&1 | tee "${HITT_LOG_FILE}"
else
  main
fi
