#!/bin/bash
# Mark_Walters@bmc.com SEAL team Aug 2023
# This script is provided as-is and BMC accepts no responsibility for problems arising from use.

# Set the hostname of your registry server or use -t option
TARGET_REGISTRY=""
SOURCE_REGISTRY=""
NUM_ACTIONS=2

# Script variables - DO NOT MODIFY
IMAGE_FILE=""
IMAGE_ARRAY=()
declare -A REGISTRY_ARRAY
DISK_REQUIRED=10
SKIP_LOGIN=F
DIND_ENABLED=F
DIND_STARTED=F
DIND_CONTAINER_RUNNING=F
DIND_IMAGE="docker.io/library/docker:dind"
DIND_CONTAINER="imagemgr-dind-$$"
DIND_PORT="${IMAGEMGR_DIND_PORT:-2375}"
DIND_DOCKER_HOST=""
DIND_USE_EXEC=F
INSECURE_SOURCE=F
INSECURE_TARGET=F
INSECURE_REGISTRIES=()
INSECURE_REGISTRIES_CONF=""
DIND_DAEMON_JSON=""
declare -A INSECURE_SEEN
CONTAINER_ENGINE=""
CURRENT_JOBS=0
COUNT=0
FAILED=0
CONTAINER_STORAGE_DIR=""
BOLD=$'\e[1m'
NORMAL=$'\e[0m'
RED=$'\e[31m'
YELLOW=$'\e[33m'
GREEN=$'\e[32m'
BLUE=$'\e[34m'
PURPLE=$'\e[35m'

# Functions
usage() {
  echo "Usage: $0 -a <sync|pull|push|save|load|verify|compare> <-i image name|-f image file> [-t target registry] [-n <number of parallel actions>] [-k skip registry login] [-p project:newproject] [-D use docker-in-docker] [-I dind-image] [-O insecure source] [-U insecure target]"
  exit 1
}

# Run podman/docker on the host — never via the docker() image-operation wrapper.
container_engine() {
  command "${CONTAINER_ENGINE}" "$@"
}

# Host imagemgr invokes docker against the dind daemon when -D is enabled.
docker() {
  if [[ "${DIND_STARTED}" == "T" ]]; then
    if [[ "${DIND_USE_EXEC}" == "T" ]]; then
      container_engine exec -i "${DIND_CONTAINER}" docker "$@"
    else
      DOCKER_HOST="${DIND_DOCKER_HOST}" command docker "$@"
    fi
  elif [[ -n "${INSECURE_REGISTRIES_CONF}" ]]; then
    CONTAINERS_REGISTRIES_CONF="${INSECURE_REGISTRIES_CONF}" command docker "$@"
  else
    command docker "$@"
  fi
}

is_podman_docker() {
  if command -v docker >/dev/null 2>&1 && command docker --version 2>/dev/null | grep -qi podman; then
    return 0
  fi
  if command -v docker >/dev/null 2>&1 && command docker info 2>/dev/null | grep -qi podman; then
    return 0
  fi
  return 1
}

detect_container_engine() {
  [[ -n "${CONTAINER_ENGINE}" ]] && return
  if is_podman_docker && command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE=docker
  elif command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE=podman
  fi
}

stop_dind() {
  [[ "${DIND_CONTAINER_RUNNING}" == "T" ]] || return
  container_engine stop -t 10 "${DIND_CONTAINER}" >/dev/null 2>&1 || \
    container_engine rm -f "${DIND_CONTAINER}" >/dev/null 2>&1 || true
  DIND_STARTED=F
  DIND_CONTAINER_RUNNING=F
  DIND_DOCKER_HOST=""
}

cleanup_insecure_configs() {
  [[ -n "${DIND_DAEMON_JSON}" && -f "${DIND_DAEMON_JSON}" ]] && rm -f "${DIND_DAEMON_JSON}"
  [[ -n "${INSECURE_REGISTRIES_CONF}" && -f "${INSECURE_REGISTRIES_CONF}" ]] && rm -f "${INSECURE_REGISTRIES_CONF}"
}

add_insecure_registry() {
  local host="${1}"

  [[ -z "${host}" ]] && return
  [[ -n "${INSECURE_SEEN[${host}]}" ]] && return
  INSECURE_SEEN["${host}"]=1
  INSECURE_REGISTRIES+=("${host}")
}

collect_insecure_registries() {
  local image=""

  if [[ "${INSECURE_TARGET}" == "T" ]]; then
    if [[ -z "${TARGET_REGISTRY}" ]]; then
      echo "Error: -U requires -t target registry."
      exit 1
    fi
    add_insecure_registry "$(registry_host "${TARGET_REGISTRY}")"
  fi

  if [[ "${INSECURE_SOURCE}" == "T" ]]; then
    for image in "${IMAGE_ARRAY[@]}"; do
      add_insecure_registry "$(registry_host "${image}")"
    done
  fi
}

write_dind_daemon_json() {
  DIND_DAEMON_JSON=$(mktemp "${TMPDIR:-/tmp}/imagemgr-daemon.XXXXXX.json")
  jq -n --argjson hosts "$(printf '%s\n' "${INSECURE_REGISTRIES[@]}" | jq -R . | jq -s .)" \
    '{ "insecure-registries": $hosts }' > "${DIND_DAEMON_JSON}"
}

write_podman_registries_conf() {
  local host=""
  INSECURE_REGISTRIES_CONF=$(mktemp "${TMPDIR:-/tmp}/imagemgr-registries.XXXXXX.conf")
  : > "${INSECURE_REGISTRIES_CONF}"
  for host in "${INSECURE_REGISTRIES[@]}"; do
    cat >> "${INSECURE_REGISTRIES_CONF}" <<EOF
[[registry]]
location = "${host}"
insecure = true

EOF
  done
}

setup_insecure_registries() {
  if [[ "${INSECURE_SOURCE}" != "T" && "${INSECURE_TARGET}" != "T" ]]; then
    return
  fi

  collect_insecure_registries
  if [[ ${#INSECURE_REGISTRIES[@]} -eq 0 ]]; then
    return
  fi

  echo "Insecure registries: ${INSECURE_REGISTRIES[*]}"

  if [[ "${DIND_ENABLED}" == "T" ]]; then
    write_dind_daemon_json
  elif is_podman_docker || command -v podman >/dev/null 2>&1; then
    write_podman_registries_conf
  else
    echo "Warning: -O/-U requires -D on host Docker — add insecure-registries to /etc/docker/daemon.json manually."
    INSECURE_REGISTRIES=()
  fi
}

start_dind() {
  local wait_secs=0
  local -a mount_args=()
  local -a env_args=(-e DOCKER_TLS_CERTDIR=)

  detect_container_engine
  if [[ -z "${CONTAINER_ENGINE}" ]]; then
    echo "DinD mode requires podman or docker on the host to run the sidecar container."
    exit 1
  fi

  DIND_DOCKER_HOST="tcp://127.0.0.1:${DIND_PORT}"
  echo "Starting docker-in-docker sidecar (${DIND_IMAGE}) via ${CONTAINER_ENGINE}..."

  # Mount host trust store into the sidecar.
  # RHEL: use the extracted bundle file — /etc/ssl/certs symlinks break inside dind.
  if [[ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]]; then
    mount_args+=(-v "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:/tmp/imagemgr-ca-bundle.pem:ro")
    env_args+=(-e SSL_CERT_FILE=/tmp/imagemgr-ca-bundle.pem)
  elif [[ -d /etc/ssl/certs ]]; then
    mount_args+=(-v "/etc/ssl/certs:/etc/ssl/certs:ro")
  fi
  if [[ -d "${HOME}/.docker" ]]; then
    mount_args+=(-v "${HOME}/.docker:/root/.docker")
  fi
  if [[ -n "${DIND_DAEMON_JSON}" && -f "${DIND_DAEMON_JSON}" ]]; then
    mount_args+=(-v "${DIND_DAEMON_JSON}:/etc/docker/daemon.json:ro")
  fi

  if ! container_engine run -d --rm --privileged \
    --name "${DIND_CONTAINER}" \
    -p "127.0.0.1:${DIND_PORT}:2375" \
    "${env_args[@]}" \
    "${mount_args[@]}" \
    "${DIND_IMAGE}"; then
    echo "Failed to start docker-in-docker sidecar."
    exit 1
  fi
  DIND_CONTAINER_RUNNING=T

  echo -n "Waiting for Docker daemon in sidecar"
  while (( wait_secs < 120 )); do
    if DOCKER_HOST="${DIND_DOCKER_HOST}" command docker info >/dev/null 2>&1; then
      echo " ready."
      DIND_STARTED=T
      DIND_USE_EXEC=F
      echo "Host docker CLI will use DOCKER_HOST=${DIND_DOCKER_HOST}"
      return 0
    fi
    if container_engine exec "${DIND_CONTAINER}" docker info >/dev/null 2>&1; then
      echo " ready."
      DIND_STARTED=T
      DIND_USE_EXEC=T
      echo "Host docker CLI cannot use DOCKER_HOST; using exec into sidecar instead."
      return 0
    fi
    echo -n "."
    sleep 2
    ((wait_secs += 2))
  done
  echo
  echo "Timed out waiting for Docker daemon in dind sidecar."
  exit 1
}

pull_image() {
  check_disk_space "${CONTAINER_STORAGE_DIR}"
  log_result "Pulling ${SOURCE_IMAGE}" ${YELLOW}
  if ! docker pull -q "${SOURCE_IMAGE}" > /dev/null; then
    log_error "pull" "${SOURCE_IMAGE}"
    exit 1
  fi
}

tag_image() {
  log_result "Tagging ${SOURCE_IMAGE} as ${TARGET_IMAGE}" ${BLUE}
  if ! docker tag "${SOURCE_IMAGE}" "${TARGET_IMAGE}"; then
    log_error "tag" "${SOURCE_IMAGE}"
    exit 1
  fi
}

push_image() {
  registry_login "$(registry_host "${TARGET_IMAGE}")"
  log_result "Pushing ${TARGET_IMAGE}" ${PURPLE}
  if ! docker push -q "${TARGET_IMAGE}" > /dev/null; then
    log_error "push" "${TARGET_IMAGE}"
    echo "Push failed — if you see 401 Unauthorized, check registry push permissions for this repository,"
    echo "or run: docker logout $(registry_host "${TARGET_IMAGE}") and log in with a push-capable account."
    exit 1
  fi
}

save_image() {
  check_disk_space "$(pwd)"
  log_result "Saving ${SOURCE_IMAGE}" ${YELLOW}
  if ! docker save "${SOURCE_IMAGE}" | gzip > "${IMAGE_FILENAME}" ; then
    log_error "save" "${SOURCE_IMAGE}"
    exit 1
  fi
}

load_image() {
  log_result "Loading ${SOURCE_IMAGE}" ${YELLOW}
  if ! docker load < "${IMAGE_FILENAME}" > /dev/null; then
    log_error "load" "${SOURCE_IMAGE}"
    exit 1
  fi
}

delete_image() {
  log_result "Deleting local image ${1}" ${YELLOW}
  if ! docker rmi "${1}" >/dev/null; then
    log_error "delete" "${1}"
    exit 1
  fi
  log_result "Deleted ${1} from the local system." ${GREEN}
}

verify_image() {
  log_result "Verifying image ${1}" ${YELLOW}
  if ! docker manifest inspect "${1}" >/dev/null; then
    log_error "verify" "${1}"
    log_missing "${1}"
    exit 1
  fi
  log_result "Image ${1} found." ${GREEN}
}

# Returns linux/amd64 config or manifest digest for compare, or empty on failure.
image_amd64_digest() {
  local image="$1"
  local manifest

  manifest=$(docker manifest inspect "${image}" 2>/dev/null) || return 1

  jq -r '
    if .manifests then
      (.manifests[]
        | select(.platform.os == "linux" and .platform.architecture == "amd64")
        | .digest) // empty
    else
      .config.digest // empty
    end
  ' <<< "${manifest}"
}

compare_images() {
  log_result "Comparing images ${SOURCE_IMAGE} / ${TARGET_IMAGE}" ${YELLOW}
  SOURCE_DIGEST=$(image_amd64_digest "${SOURCE_IMAGE}")
  if [[ -z "${SOURCE_DIGEST}" ]]; then
    log_error "find" "${SOURCE_IMAGE}"
    exit 1
  fi

  TARGET_DIGEST=$(image_amd64_digest "${TARGET_IMAGE}")
  if [[ -z "${TARGET_DIGEST}" ]]; then
    log_error "find" "${TARGET_IMAGE}"
    exit 1
  fi

  if [[ "${SOURCE_DIGEST}" != "${TARGET_DIGEST}" ]]; then
    log_error "compare" "${TARGET_IMAGE}"
    exit 1
  else
    log_result "Images ${SOURCE_IMAGE} and ${TARGET_IMAGE} match (linux/amd64)." ${GREEN}
  fi
}

# Return registry host[:port] from a full image ref or registry/project prefix.
registry_host() {
  echo "${1%%/*}"
}

is_docker_hub_registry() {
  local registry="${1}"

  registry="${registry%%/*}"
  registry="${registry,,}"
  case "${registry}" in
    docker.io|index.docker.io|registry-1.docker.io) return 0 ;;
  esac
  return 1
}

registry_login_password() {
  local registry="${1}"
  local user="${2}"
  local pass="${3}"

  if [[ "${DIND_STARTED}" == "T" && "${DIND_USE_EXEC}" == "T" ]]; then
    echo "${pass}" | container_engine exec -i "${DIND_CONTAINER}" \
      docker login -u "${user}" --password-stdin "${registry}"
  elif [[ "${DIND_STARTED}" == "T" ]]; then
    echo "${pass}" | DOCKER_HOST="${DIND_DOCKER_HOST}" command docker \
      login -u "${user}" --password-stdin "${registry}"
  else
    echo "${pass}" | command docker login -u "${user}" --password-stdin "${registry}"
  fi
}

registry_login_interactive_user() {
  local registry="${1}"
  local user="${2}"

  if [[ "${DIND_STARTED}" == "T" && "${DIND_USE_EXEC}" == "T" ]]; then
    container_engine exec -it "${DIND_CONTAINER}" docker login -u "${user}" "${registry}"
  elif [[ "${DIND_STARTED}" == "T" ]]; then
    DOCKER_HOST="${DIND_DOCKER_HOST}" command docker login -u "${user}" "${registry}"
  else
    command docker login -u "${user}" "${registry}"
  fi
}

registry_login_stdin() {
  local registry="${1}"

  registry_login_password "${registry}" "${IMAGEMGR_REGISTRY_USER}" "${IMAGEMGR_REGISTRY_PASS}"
}

registry_login_docker_hub() {
  local registry="${1}"
  local user="${IMAGEMGR_DOCKERIO_USER:-${IMAGEMGR_REGISTRY_USER:-}}"
  local pass="${IMAGEMGR_DOCKERIO_PASS:-${IMAGEMGR_REGISTRY_PASS:-}}"

  if [[ -n "${user}" && -n "${pass}" ]]; then
    registry_login_password "${registry}" "${user}" "${pass}"
    return
  fi

  if [[ -n "${user}" ]]; then
    registry_login_interactive_user "${registry}" "${user}"
    return
  fi

  if [[ -t 0 ]]; then
    read -rp "Docker Hub username: " user
    registry_login_interactive_user "${registry}" "${user}"
    return
  fi

  echo "Docker Hub login requires a username to avoid web-based login."
  echo "Set IMAGEMGR_DOCKERIO_USER and IMAGEMGR_DOCKERIO_PASS (or IMAGEMGR_REGISTRY_USER/PASS)."
  return 1
}

registry_login() {
  local registry="${1}"

  [[ "${SKIP_LOGIN}" == "T" ]] && return
  echo "Validating login to ${registry}"

  if is_docker_hub_registry "${registry}"; then
    if ! registry_login_docker_hub "${registry}"; then
      echo "Failed to login to registry server - ${registry}"
      exit 1
    fi
    return
  fi

  if [[ -n "${IMAGEMGR_REGISTRY_USER}" && -n "${IMAGEMGR_REGISTRY_PASS}" ]]; then
    if ! registry_login_stdin "${registry}"; then
      echo "Failed to login to registry server - ${registry}"
      exit 1
    fi
    return
  fi

  if [[ "${DIND_STARTED}" == "T" && "${DIND_USE_EXEC}" == "T" ]]; then
    if ! container_engine exec -it "${DIND_CONTAINER}" docker login "${registry}"; then
      echo "Failed to login to registry server - ${registry}"
      exit 1
    fi
    return
  fi

  if ! docker login "${registry}"; then
    echo "Failed to login to registry server - ${registry}"
    exit 1
  fi
}

# Resolve container image store (Docker or Podman via docker alias).
get_container_storage_dir() {
  local dir=""

  dir=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)
  if [[ -n "${dir}" && "${dir}" != "<no value>" ]]; then
    echo "${dir}"
    return 0
  fi

  dir=$(docker info --format '{{.Store.GraphRoot}}' 2>/dev/null)
  if [[ -n "${dir}" && "${dir}" != "<no value>" ]]; then
    echo "${dir}"
    return 0
  fi

  if command -v podman >/dev/null 2>&1; then
    dir=$(podman info --format '{{.Store.GraphRoot}}' 2>/dev/null)
    if [[ -n "${dir}" && "${dir}" != "<no value>" ]]; then
      echo "${dir}"
      return 0
    fi
  fi

  for dir in /var/lib/docker /var/lib/containers/storage "${HOME}/.local/share/containers/storage"; do
    if [[ -d "${dir}" ]]; then
      echo "${dir}"
      return 0
    fi
  done

  return 1
}

# Returns available space in whole GB for path, or empty on failure.
get_disk_avail_gb() {
  local path="$1"
  local avail_kb=""

  # GNU df: --output=avail (cannot combine with -P)
  if avail_kb=$(df -k --output=avail "${path}" 2>/dev/null | awk 'NR==2 {print $1; exit}'); then
    if [[ -n "${avail_kb}" && "${avail_kb}" =~ ^[0-9]+$ ]]; then
      awk -v kb="${avail_kb}" 'BEGIN {printf "%.0f\n", kb/1024/1024}'
      return 0
    fi
  fi

  # POSIX df -kP: Available is column 4
  avail_kb=$(df -kP "${path}" 2>/dev/null | awk 'NR==2 {print $4; exit}')
  if [[ -n "${avail_kb}" && "${avail_kb}" =~ ^[0-9]+$ ]]; then
    awk -v kb="${avail_kb}" 'BEGIN {printf "%.0f\n", kb/1024/1024}'
    return 0
  fi

  return 1
}

check_disk_space() {
  local target="${1}"
  local check_path="${target}"
  local parent=""
  local disk_avail=""

  if [[ -z "${target}" ]]; then
    echo "Unable to determine container storage path for disk space check."
    exit 1
  fi

  while [[ ! -e "${check_path}" ]]; do
    parent=$(dirname "${check_path}")
    if [[ "${parent}" == "${check_path}" ]]; then
      echo "Storage path '${target}' does not exist and could not be resolved."
      exit 1
    fi
    check_path="${parent}"
  done

  disk_avail=$(get_disk_avail_gb "${check_path}") || true
  if [[ -z "${disk_avail}" || ! "${disk_avail}" =~ ^[0-9]+$ ]]; then
    echo "Unable to check free disk space for ${target}"
    exit 1
  fi

  if (( disk_avail < DISK_REQUIRED )); then
    echo "Not enough free disk space in ${target}"
    echo "${DISK_REQUIRED}GB required / ${disk_avail}GB available"
    exit 1
  fi
}

check_tools(){
  local tool=""
  local -a tools=(docker dos2unix jq)

  if [[ "${DIND_ENABLED}" == "T" ]]; then
    detect_container_engine
    if [[ -z "${CONTAINER_ENGINE}" ]]; then
      echo -e "\nError - DinD mode requires podman or docker on the host to run the sidecar."
      exit 1
    fi
  fi

  for tool in "${tools[@]}"; do
    if ! which "${tool}" > /dev/null 2>&1; then
      echo -e "\nError - Missing required command line tool - please install ${tool}"
      exit 1
    fi
  done
}

init_container_runtime() {
  setup_insecure_registries
  trap 'stop_dind; cleanup_insecure_configs' EXIT

  if [[ "${DIND_ENABLED}" == "T" ]]; then
    start_dind
  fi

  CONTAINER_STORAGE_DIR=$(get_container_storage_dir) || {
    echo "Unable to determine container storage directory from docker/podman info."
    exit 1
  }
}

process_image(){
#  IMAGE_PATH=$(echo "${SOURCE_IMAGE}" | awk -F"/" '{print $(NF-1)"/"$(NF)}' | awk -F":" '{print $1}')
#  IMAGE_TAG=$(echo "${SOURCE_IMAGE}" | awk -F":" '{print $NF}')
  IMAGE_FILENAME=$(URLEncode "${SOURCE_IMAGE}")
  TARGET_IMAGE="${TARGET_REGISTRY}/${SOURCE_IMAGE#*/}"
  if [ "${PROJECT}" != "" ]; then
    TARGET_IMAGE=$(echo "${TARGET_IMAGE}" | sed "s,/${PROJECT_SOURCE}/,/${PROJECT_TARGET}/,g")
  fi

  case ${ACTION} in
    sync)
      pull_image
      tag_image
      push_image
      delete_image "${SOURCE_IMAGE}"
      delete_image "${TARGET_IMAGE}"
      ;;
    pull)
      pull_image
      ;;
    push)
      tag_image
      push_image
      ;;
    save)
      pull_image
      save_image
      delete_image "${SOURCE_IMAGE}"
      ;;
    load)
      load_image
      tag_image
      push_image
      delete_image "${SOURCE_IMAGE}"
      delete_image "${TARGET_IMAGE}"
      ;;
    verify)
      if [ -z "$TARGET_REGISTRY" ]; then
        verify_image "${SOURCE_IMAGE}"
      else
        verify_image "${TARGET_IMAGE}" "${SOURCE_IMAGE}"
      fi
      ;;
    compare)
      compare_images
      ;;
  esac
}

# Requires $1 action $2 image name
log_error(){
  printf "${RED}%03d${NORMAL} - Failed to ${1} ${2}\n" ${COUNT} | tee -a errors.txt
}

log_result(){
  printf "${2}%03d${NORMAL} - ${1}\n" ${COUNT} | tee -a results.txt
}

log_missing() {
  echo "${1}" >> missing.txt
}

URLEncode(){
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

# END functions

# MAIN start

# Process command line
# -a sync pull push save load verify compare
# -f input file
# -i image name
# -n num of parallel actions
# -s source registry
# -t target registry
# -k skip docker login
# -D use docker-in-docker (for podman hosts)
# -I dind sidecar image
# -O insecure source registry/registries (from image list)
# -U insecure target registry (from -t)

while getopts "a:f:i:n:p:s:t:kDI:OU" options; do
  case "${options}" in
    a)
      ACTION=${OPTARG}
      ;;
    f)
      IMAGE_FILE=${OPTARG}
      ;;
    i)
      IMAGE_NAME=${OPTARG}
      ;;
    n)
      NUM_ACTIONS=${OPTARG}
      ;;
    p)
      PROJECT=${OPTARG}
      ;;
    s)
      SOURCE_REGISTRY=${OPTARG}
      ;;
    t)
      TARGET_REGISTRY=${OPTARG}
      ;;
    k)
      SKIP_LOGIN=T
      ;;
    D)
      DIND_ENABLED=T
      ;;
    I)
      DIND_IMAGE=${OPTARG}
      ;;
    O)
      INSECURE_SOURCE=T
      ;;
    U)
      INSECURE_TARGET=T
      ;;
    :)
      echo "Error: -${OPTARG} requires an argument."
      usage
      ;;
    *)
      usage
      ;;
  esac
done

# Validate action
[[ "${ACTION}" =~ ^sync$|^pull$|^save$|^push$|^load$|^verify$|^compare$ ]] || usage

  # Check for required options
  # -a sync -f/-i -t
  # -a pull -f/-i
  # -a push -f/-i -t
  # -a save -f/-i
  # -a load -f/-i -t
  # -a verify -f/-i -t optional
  # -a compare -f/-i -t

  # Action is required
  if [[ -z ${ACTION} ]]; then
    echo "Action must be specified with -a sync|pull|push|save|load|verify|compare"
    exit 1
  fi

  # TARGET_REGISTRY must be set if action is sync/push/load/compare
  if [[ ${ACTION} == "sync"  || ${ACTION} == "push" || ${ACTION} == "load" || ${ACTION} == "compare" ]]; then
    if [[ -z ${TARGET_REGISTRY} ]]; then
      echo "TARGET_REGISTRY must be set for sync/push/load/compare actions."
      exit 1
    fi
  fi

  # Either -f or -i required
  if [[ -z ${IMAGE_FILE} && -z ${IMAGE_NAME} ]]; then
    echo "Either -f image-file or -i image-name must be provided."
    exit 1
  fi

  # -f and -i are mutually exclusive
  if [[ -n ${IMAGE_FILE} && -n ${IMAGE_NAME} ]]; then
    echo "Use -f image-file or -i image-name, not both."
    exit 1
  fi

  # IMAGE_FILE must exist if -f used
  if [[ -n ${IMAGE_FILE} && ! -f ${IMAGE_FILE} ]]; then
    echo "Image file '${IMAGE_FILE}' not found.  Please check the name and try again."
    exit 1
  fi

  # -s not valid with -i
  if [[ -n ${IMAGE_NAME} && -n ${SOURCE_REGISTRY} ]]; then
    echo "Source registry (-s) not valid with image name (-i)."
    exit 1
  fi

  # Is project string valid?
  if [[ -n "${PROJECT}" ]]; then
    if [[ ! "${PROJECT}" =~ ^([^:]+):([^:]+)$ ]]; then
        echo "Project substitution string (-p ${PROJECT}) must be in 'currentproject:newproject' format."
        exit 1
    fi
    PROJECT_SOURCE="${BASH_REMATCH[1]}"
    PROJECT_TARGET="${BASH_REMATCH[2]}"
  fi

check_tools

# Build IMAGE_ARRAY to process - from input file or command with -i
if [[ -n ${IMAGE_FILE} ]]; then
  dos2unix -q "${IMAGE_FILE}"
  echo "Processing ${IMAGE_FILE}" | tee -a results.txt
  # Loop through input file line by line...
  while IFS= read -r line  || [ "$line" ]; do
    IMAGE=""
    if [[ -z "${SOURCE_REGISTRY}" ]]; then
        IMAGE="${line}"
    fi
    if [[ -n "${SOURCE_REGISTRY}" ]]; then
      IMAGE="${SOURCE_REGISTRY}/${line#*/}"
    fi
    REGISTRY_ARRAY["$(registry_host "${IMAGE}")"]=1
    #continue
    IMAGE_ARRAY+=($(echo "${IMAGE}"  | tr -d '[:space:]'))
  done < <(grep -v '^#' "${IMAGE_FILE}" | sed '/^[[:space:]]*$/d')
  echo "${#IMAGE_ARRAY[@]} image(s) to process." | tee -a results.txt
fi

# Image name provided on command line -i
if [[ -n ${IMAGE_NAME} ]]; then
  IMAGE_ARRAY=("${IMAGE_NAME}")
  REGISTRY_ARRAY["$(registry_host "${IMAGE_NAME}")"]=1
fi

init_container_runtime

# Check we are logged in to registries (target last so its credentials are freshest)
[[ -n "${TARGET_REGISTRY}" ]] && REGISTRY_ARRAY["$(registry_host "${TARGET_REGISTRY}")"]=1
TARGET_REGISTRY_HOST=""
[[ -n "${TARGET_REGISTRY}" ]] && TARGET_REGISTRY_HOST="$(registry_host "${TARGET_REGISTRY}")"
for registry in "${!REGISTRY_ARRAY[@]}"; do
  [[ -n "${TARGET_REGISTRY_HOST}" && "${registry}" == "${TARGET_REGISTRY_HOST}" ]] && continue
  registry_login "${registry}"
done
[[ -n "${TARGET_REGISTRY_HOST}" ]] && registry_login "${TARGET_REGISTRY_HOST}"

# Loop over the images in the IMAGE_ARRAY
for SOURCE_IMAGE in "${IMAGE_ARRAY[@]}"; do
  while (( CURRENT_JOBS >= NUM_ACTIONS )); do
    if ! wait -n; then
      ((FAILED++))
    fi
    ((CURRENT_JOBS--))
  done
  if [[ -n "${PROJECT}" ]] && [[ ! "${SOURCE_IMAGE}" == *"/${PROJECT_SOURCE}/"* ]]; then
    log_error "${ACTION}" "'${SOURCE_IMAGE}' does not include '/${PROJECT_SOURCE}/'."
    continue
  fi
  ((COUNT++))
  process_image "${SOURCE_IMAGE}" &
  ((CURRENT_JOBS++))
done
while (( CURRENT_JOBS > 0 )); do
  if ! wait -n; then
    ((FAILED++))
  fi
  ((CURRENT_JOBS--))
done
if (( FAILED > 0 )); then
  echo "Finished processing images with ${FAILED} failure(s)."
  exit 1
fi
echo "Finished processing images."

# Redundant code
# ITSM style image: line
#if echo  "$line" | grep "image: " > /dev/null; then
#  IMAGE_PATH=$(echo -n "$line" | awk 'BEGIN {ORS=""} {print $2}')
#fi
# ITSM style imagetag: line
#if echo  "$line" | grep "imagetag: " > /dev/null; then
#  IMAGE_TAG=$(echo "$line" | awk '{print $2}')
#  IMAGE="${SOURCE_REGISTRY}/${IMAGE_PATH}:${IMAGE_TAG}"
#fi
# ITOM style containers.bmc.com line
