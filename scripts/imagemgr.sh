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
  echo "Usage: $0 -a <sync|pull|push|save|load|verify|compare> <-i image name|-f image file> [-t target registry] [-n <number of parallel actions>] [-k skip registry login] [-p project:newproject]"
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
  log_result "Pushing ${TARGET_IMAGE}" ${PURPLE}
  if ! docker push -q "${TARGET_IMAGE}" > /dev/null; then
    log_error "push" "${TARGET_IMAGE}"
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

registry_login() {
  [[ "${SKIP_LOGIN}" == "T" ]] && return
  echo "Validating login to ${1}"
  if ! docker login "${1}"; then
    echo "Failed to login to registry server - ${1}"
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
  # Check we have the tools we need
  TOOLS=(docker dos2unix jq)
  for TOOL in "${TOOLS[@]}"; do
    if ! which "${TOOL}" > /dev/null 2>&1; then
      echo -e "\nError - Missing required command line tool - please install ${TOOL}"
      exit 1
    fi
  done

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

while getopts "a:f:i:n:p:s:t:k" options; do
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
# Read list of images from file
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
    REGISTRY_ARRAY["${IMAGE%%/*}"]=1
    #continue
    IMAGE_ARRAY+=($(echo "${IMAGE}"  | tr -d '[:space:]'))
  done < <(grep -v '^#' "${IMAGE_FILE}" | sed '/^[[:space:]]*$/d')
  echo "${#IMAGE_ARRAY[@]} image(s) to process." | tee -a results.txt
fi

# Image name provided on command line -i
if [[ -n ${IMAGE_NAME} ]]; then
  IMAGE_ARRAY=("${IMAGE_NAME}")
  REGISTRY_ARRAY["${IMAGE_NAME%%/*}"]=1
fi

# Check we are logged in to registries
[[ -n "${TARGET_REGISTRY}" ]] && REGISTRY_ARRAY["${TARGET_REGISTRY}"]=1
for registry in "${!REGISTRY_ARRAY[@]}"
do
  registry_login "${registry}"
done

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
