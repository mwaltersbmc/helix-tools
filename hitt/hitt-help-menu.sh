#!/usr/bin/env bash
# Standalone menu-driven HITT help from docs/hitt/use-cases.json.
# Prefer: bash hitt.sh -h usecases  (embedded JSON, no repo clone required).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEFAULT_USE_CASES_JSON="${SCRIPT_DIR}/../docs/hitt/use-cases.json"
USE_CASES_JSON_FILE="${DEFAULT_USE_CASES_JSON}"
USE_CASES_JSON_SOURCE="file"
JQ_BIN="${JQ_BIN:-jq}"

usage() {
  cat <<EOF
Usage: bash $(basename "$0") [OPTIONS]

Interactive menu of HITT use cases from use-cases.json.

Options:
  -f PATH   Path to use-cases.json (default: ${DEFAULT_USE_CASES_JSON})
  -h        Show this help

Environment:
  HITT_USE_CASES_JSON   Embedded JSON from hitt.sh (when sourced there)
  JQ_BIN                jq executable (default: jq)
EOF
}

while getopts ":f:h" opt; do
  case "${opt}" in
    f) USE_CASES_JSON_FILE="${OPTARG}"; USE_CASES_JSON_SOURCE="file" ;;
    h)
      usage
      exit 0
      ;;
    :)
      echo "Option -${OPTARG} requires an argument." >&2
      exit 1
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

require_jq() {
  if ! command -v "${JQ_BIN}" >/dev/null 2>&1; then
    echo "error: ${JQ_BIN} is required but not found on PATH." >&2
    exit 1
  fi
}

use_cases_json_init() {
  if [[ -n "${HITT_USE_CASES_JSON:-}" && "${HITT_USE_CASES_JSON}" == \{* ]]; then
    USE_CASES_JSON_SOURCE="env"
    return 0
  fi
  USE_CASES_JSON_SOURCE="file"
}

use_cases_jq() {
  if [[ "${USE_CASES_JSON_SOURCE}" == "env" ]]; then
    "${JQ_BIN}" "$@" <<< "${HITT_USE_CASES_JSON}"
  else
    "${JQ_BIN}" "$@" "${USE_CASES_JSON_FILE}"
  fi
}

require_use_cases_json() {
  use_cases_json_init
  if [[ "${USE_CASES_JSON_SOURCE}" == "file" ]]; then
    if [[ ! -f "${USE_CASES_JSON_FILE}" ]]; then
      echo "error: use-cases file not found: ${USE_CASES_JSON_FILE}" >&2
      echo "Clone helix-tools or set -f." >&2
      exit 1
    fi
  fi
  if ! use_cases_jq -e '.topics and .useCases' >/dev/null 2>&1; then
    echo "error: invalid use-cases JSON." >&2
    exit 1
  fi
}

use_cases_json_display_path() {
  if [[ "${USE_CASES_JSON_SOURCE}" == "env" ]]; then
    echo "embedded in hitt.sh"
    return 0
  fi
  local dir base
  dir=$(cd "$(dirname "${USE_CASES_JSON_FILE}")" && pwd)
  base=$(basename "${USE_CASES_JSON_FILE}")
  echo "${dir}/${base}"
}

# Print numbered menu to stderr; echo selected 1-based index on stdout.
menu_select_index() {
  local -a options=("$@")
  local i reply

  [[ ${#options[@]} -gt 0 ]] || return 1
  for i in "${!options[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${options[$i]}" >&2
  done
  while true; do
    read -r -p "Select (1-${#options[@]}): " reply
    if [[ "${reply}" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= ${#options[@]} )); then
      echo "${reply}"
      return 0
    fi
    echo "Invalid choice: ${reply}" >&2
  done
}

load_topic_menu() {
  local -a ids=() titles=()
  local id title

  while IFS=$'\t' read -r id title; do
    id=${id//$'\r'/}
    title=${title//$'\r'/}
    [[ -n "${id}" ]] || continue
    ids+=("${id}")
    titles+=("${title}")
  done < <(use_cases_jq -r '.topics | sort_by(.order)[] | [.id, .title] | @tsv')

  TOPIC_IDS=("${ids[@]}")
  TOPIC_TITLES=("${titles[@]}")
}

load_use_case_menu() {
  local topic_id="${1}"
  local -a ids=() titles=()
  local id title

  while IFS=$'\t' read -r id title; do
    id=${id//$'\r'/}
    title=${title//$'\r'/}
    [[ -n "${id}" ]] || continue
    ids+=("${id}")
    titles+=("${title}")
  done < <(use_cases_jq -r --arg tid "${topic_id}" \
    '.useCases | map(select(.topicId == $tid)) | sort_by(.order)[] | [.id, .title] | @tsv')

  UC_IDS=("${ids[@]}")
  UC_TITLES=("${titles[@]}")
}

use_cases_help_url() {
  use_cases_jq -r '.meta.helpBaseUrl // "https://mwaltersbmc.github.io/helix-tools/hitt/index.html"'
}

use_cases_direct_url() {
  local use_case_id="${1}"
  local base
  base=$(use_cases_help_url)
  base=${base//$'\r'/}
  base=${base%/}
  echo "${base}#use-case-${use_case_id}"
}

show_use_case_detail() {
  local use_case_id="${1}"
  local title see_also

  title=$(use_cases_jq -r --arg id "${use_case_id}" \
    '.useCases[] | select(.id == $id) | .title')
  title=${title//$'\r'/}
  [[ -n "${title}" && "${title}" != "null" ]] || {
    echo "Use case not found: ${use_case_id}" >&2
    return 1
  }

  echo
  echo "================================================================"
  echo "${title}"
  echo "================================================================"
  echo
  echo "Help link:"
  echo "  $(use_cases_direct_url "${use_case_id}")"
  echo

  if use_cases_jq -e --arg id "${use_case_id}" \
    '.useCases[] | select(.id == $id) | (.commands | length) > 0' >/dev/null; then
    echo "Commands:"
    use_cases_jq -r --arg id "${use_case_id}" \
      '.useCases[] | select(.id == $id) | .commands[]' \
      | while IFS= read -r cmd; do
          cmd=${cmd//$'\r'/}
          echo "  ${cmd}"
        done
    echo
  fi

  if use_cases_jq -e --arg id "${use_case_id}" \
    '.useCases[] | select(.id == $id) | (.notes | length) > 0' >/dev/null; then
    echo "Notes:"
    use_cases_jq -r --arg id "${use_case_id}" \
      '.useCases[] | select(.id == $id) | .notes[]' \
      | while IFS= read -r note; do
          note=${note//$'\r'/}
          echo "  - ${note}"
        done
    echo
  fi

  see_also=$(use_cases_jq -r --arg id "${use_case_id}" \
    '.useCases[] | select(.id == $id) | .seeAlso // empty')
  see_also=${see_also//$'\r'/}
  if [[ -n "${see_also}" ]]; then
    echo "See also:"
    echo "  ${see_also}"
    echo
  fi

  read -r -s -n 1 -p "Press Enter to return to use cases or q to quit... " reply
  echo
  if [[ "${reply}" == "q" || "${reply}" == "Q" ]]; then
    return 1
  fi
  return 0
}

menu_topics() {
  local -a menu_labels=()
  local sel topic_count

  while true; do
    load_topic_menu
    topic_count=${#TOPIC_TITLES[@]}
    ((${topic_count} > 0)) || {
      echo "No topics found in use-cases data." >&2
      return 1
    }

    menu_labels=("${TOPIC_TITLES[@]}" "Quit")
    echo
    echo "HITT use cases — choose a topic"
    echo "Source: $(use_cases_json_display_path)"
    sel=$(menu_select_index "${menu_labels[@]}")
    if (( sel == topic_count + 1 )); then
      return 0
    fi
    menu_use_cases "${TOPIC_IDS[$((sel - 1))]}" "${TOPIC_TITLES[$((sel - 1))]}"
  done
}

menu_use_cases() {
  local topic_id="${1}"
  local topic_title="${2}"
  local -a menu_labels=()
  local sel uc_count

  while true; do
    load_use_case_menu "${topic_id}"
    uc_count=${#UC_TITLES[@]}
    if ((${uc_count} == 0)); then
      echo "No use cases for topic: ${topic_title}" >&2
      read -r -p "Press Enter to return to topics... "
      return 0
    fi

    menu_labels=("${UC_TITLES[@]}" "Back to topics")
    echo
    echo "${topic_title} — choose a use case"
    sel=$(menu_select_index "${menu_labels[@]}")
    if (( sel == uc_count + 1 )); then
      return 0
    fi
    show_use_case_detail "${UC_IDS[$((sel - 1))]}" || exit 0
  done
}

main() {
  local tool_name
  require_jq
  require_use_cases_json
  tool_name=$(use_cases_jq -r '.meta.tool // "HITT"')
  tool_name=${tool_name//$'\r'/}
  echo "${tool_name} — interactive use-case guide"
  menu_topics
}

if [[ ! -t 0 ]]; then
  echo "error: interactive terminal required." >&2
  exit 1
fi

main
