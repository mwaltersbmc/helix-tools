#!/bin/bash
# Mark_Walters@bmc.com SEAL team Aug 2023
# This script is provided as-is and BMC accepts no responsibilty for problems arising from use.

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
DOCKER_ROOT_DIR=$(docker info --format '{{json .DockerRootDir}}' | tr -d \")

# Functions
usage() {
  echo "Usage: $0 -a <sync|pull|push|save|load|verify|compare> <-i image name|-f image file> [-t target registry] [-n <number of parallel actions>] [-k skip registry login]"
  exit 1
}

pull_image() {
  check_disk_space "${DOCKER_ROOT_DIR}"
  log_result "Pulling ${SOURCE_IMAGE}"
  if ! docker pull -q "${SOURCE_IMAGE}" > /dev/null; then
    log_error "pull" "${SOURCE_IMAGE}"
    exit
  fi
}

tag_image() {
  log_result "Tagging ${SOURCE_IMAGE} as ${TARGET_IMAGE}"
  if ! docker tag "${SOURCE_IMAGE}" "${TARGET_IMAGE}"; then
    log_error "tag" "${SOURCE_IMAGE}"
    exit
  fi
}

push_image() {
  log_result "Pushing ${TARGET_IMAGE}"
  if ! docker push -q "${TARGET_IMAGE}" > /dev/null; then
    log_error "push" "${TARGET_IMAGE}"
    exit
  fi
}

save_image() {
  check_disk_space $(pwd)
  log_result "Saving ${SOURCE_IMAGE}"
  if ! docker save "${SOURCE_IMAGE}" | gzip > "${IMAGE_FILENAME}" ; then
    log_error "save" "${SOURCE_IMAGE}"
    exit
  fi
}

load_image() {
  log_result "Loading ${SOURCE_IMAGE}"
  if ! docker load < "${IMAGE_FILENAME}" > /dev/null; then
    log_error "load" "${SOURCE_IMAGE}"
    exit
  fi
}

delete_image() {
  log_result "Deleting local image ${1}"
  if ! docker rmi "${1}" >/dev/null; then
    log_error "delete" "${1}"
    exit
  fi
  log_result "Deleted ${1} from the local system."
}

verify_image() {
  log_result "Verifying image ${1}"
  if ! docker manifest inspect "${1}" >/dev/null; then
    log_error "verify" "${1}"
    exit
  fi
  log_result "Image ${1} found."
}

compare_images() {
  log_result "Comparing images ${SOURCE_IMAGE} / ${TARGET_IMAGE}"
  SOURCE_DIGEST=""
  TARGET_DIGEST=""
  SOURCE_DIGEST=$(docker manifest inspect "${SOURCE_IMAGE}" 2>/dev/null | jq .config.digest)
  if [[ -z "${SOURCE_DIGEST}" ]]; then
    log_error "find" "${SOURCE_IMAGE}"
    exit
  fi

  TARGET_DIGEST=$(docker manifest inspect "${TARGET_IMAGE}" 2>/dev/null | jq .config.digest)
  if [[ -z "${TARGET_DIGEST}" ]]; then
    log_error "find" "${TARGET_IMAGE}"
    exit
  fi

  if [[ "${SOURCE_DIGEST}" != "${TARGET_DIGEST}" ]]; then
    log_error "compare" "${TARGET_IMAGE}"
    exit
  else
    log_result "Images ${SOURCE_IMAGE} and ${TARGET_IMAGE} match."
  fi
}

registry_login() {
  [[ "${SKIP_LOGIN}" == "T" ]] && return
  echo "Validating login to $1"
  if ! docker login $1; then
    echo "Failed to login to registry server - $1"
    exit 1
  fi
}

check_disk_space() {
  DISK_AVAIL=$(df -k --output=avail $1 | grep -v 'Avail' | awk '{print $1/1024/1024}' | awk '{printf "%.0f\n", $1}')
  if (( ${DISK_AVAIL} < ${DISK_REQUIRED} )); then
    echo "Not enough free disk space in $1"
    echo "${DISK_REQUIRED}GB required / ${DISK_AVAIL}GB available"
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
}

process_image(){
#  IMAGE_PATH=$(echo "${SOURCE_IMAGE}" | awk -F"/" '{print $(NF-1)"/"$(NF)}' | awk -F":" '{print $1}')
#  IMAGE_TAG=$(echo "${SOURCE_IMAGE}" | awk -F":" '{print $NF}')
  IMAGE_FILENAME=$(URLEncode "${SOURCE_IMAGE}")
  TARGET_IMAGE="${TARGET_REGISTRY}/${SOURCE_IMAGE#*/}"

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
  printf "%03d - Failed to ${1} ${2}\n" ${COUNT} | tee -a errors.txt
}

log_result(){
  printf "%03d - ${1}\n" ${COUNT} | tee -a results.txt
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

while getopts "a:f:i:n:s:t:k" options; do
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
    echo "Either -f image file or -i image name must be provided."
    exit 1
  fi

  # IMAGE_FILE must exist if -f used
  if [[ -n ${IMAGE_FILE} && ! -f ${IMAGE_FILE} ]]; then
    echo "Image file ${IMAGE_FILE} not found.  Please check the name and try again."
    exit 1
  fi

  # -s not valid with -i
  if [[ -n ${IMAGE_NAME} && -n ${SOURCE_REGISTRY} ]]; then
    echo "Source registry (-s) not valid with image name (-i).  Change the image name and try again."
    exit 1
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
  done < <(cat ${IMAGE_FILE} | grep -v '^#' | sed '/^[[:space:]]*$/d')
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
  while [ $CURRENT_JOBS -ge $NUM_ACTIONS ]; do
    sleep 1
    CURRENT_JOBS=$(jobs | wc -l)
  done
  ((COUNT++))
  process_image "${SOURCE_IMAGE}" &
  CURRENT_JOBS=$(jobs | wc -l)
done
#printf '%s\n' "${!REGISTRY_ARRAY[@]}"
# Wait for final image to be processed
wait
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
