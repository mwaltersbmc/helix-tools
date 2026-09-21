#!/usr/bin/env bash
# Embed AR server info JSON into hitt/hitt.sh as AR_SERVER_INFO_JSON (heredoc).
#
# Usage:
#   pwsh -File scripts/gen-ar-server-info-json.ps1 | bash scripts/embed-hitt-ar-server-info.sh
#   bash scripts/embed-hitt-ar-server-info.sh path/to.json
#   bash scripts/embed-hitt-ar-server-info.sh --check   # reads JSON from stdin
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HITT_SH="${ROOT}/hitt/hitt.sh"
BEGIN_MARKER='# BEGIN AR_SERVER_INFO_JSON'
END_MARKER='# END AR_SERVER_INFO_JSON'
CHECK_ONLY=0
JSON_INPUT=""

if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
  shift
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "embed-hitt-ar-server-info: jq is required but not on PATH." >&2
  exit 1
fi

[[ -f "${HITT_SH}" ]] || {
  echo "embed-hitt-ar-server-info: missing ${HITT_SH}" >&2
  exit 1
}

if [[ -n "${1:-}" ]]; then
  [[ -f "${1}" ]] || {
    echo "embed-hitt-ar-server-info: missing ${1}" >&2
    exit 1
  }
  JSON_INPUT="$(<"${1}")"
elif [[ ! -t 0 ]]; then
  JSON_INPUT="$(cat)"
else
  echo "embed-hitt-ar-server-info: provide JSON on stdin or as a file argument." >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

block_file="${tmp_dir}/embed-block.txt"
current_block="${tmp_dir}/current-block.txt"
pretty_json="${tmp_dir}/pretty.json"

jq -e 'type=="array" and length>0 and (.[0]|type=="object") and (.[0].name|type=="string") and (.[0].id|type=="number")' <<< "${JSON_INPUT}" >/dev/null
jq . <<< "${JSON_INPUT}" > "${pretty_json}"

{
  printf '%s\n' "${BEGIN_MARKER}"
  printf '%s\n' "read -r -d '' AR_SERVER_INFO_JSON <<'AR_SERVER_INFO_JSON_EOF' || true"
  cat "${pretty_json}"
  printf '%s\n' "AR_SERVER_INFO_JSON_EOF"
  printf '%s\n' "${END_MARKER}"
} > "${block_file}"

extract_embed_block() {
  local file="${1}"
  local out="${2}"
  awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" '
    $0 == begin { capture=1 }
    capture { print }
    $0 == end { capture=0 }
  ' "${file}" > "${out}"
}

write_embed_block() {
  local target="${1}"
  local block="${2}"
  local tmp="${target}.embed.$$"

  if grep -q "^${BEGIN_MARKER}$" "${target}"; then
    awk -v begin="${BEGIN_MARKER}" -v end="${END_MARKER}" -v blockfile="${block}" '
      $0 == begin {
        while ((getline line < blockfile) > 0) print line
        close(blockfile)
        skip=1
        next
      }
      $0 == end { skip=0; next }
      !skip { print }
    ' blockfile="${block}" "${target}" > "${tmp}"
  else
    awk -v blockfile="${block}" '
      $0 == "# END HITT_USE_CASES_JSON" {
        print
        while ((getline line < blockfile) > 0) print line
        close(blockfile)
        next
      }
      { print }
    ' blockfile="${block}" "${target}" > "${tmp}"
  fi

  mv -f "${tmp}" "${target}"
}

if [[ "${CHECK_ONLY}" == "1" ]]; then
  if ! grep -q "^${BEGIN_MARKER}$" "${HITT_SH}"; then
    echo "embed-hitt-ar-server-info: ${HITT_SH} is missing ${BEGIN_MARKER}" >&2
    exit 1
  fi
  extract_embed_block "${HITT_SH}" "${current_block}"
  if ! diff -u "${current_block}" "${block_file}"; then
    echo "embed-hitt-ar-server-info: embedded AR server info is out of date. Run: pwsh -File scripts/gen-ar-server-info-json.ps1 | bash scripts/embed-hitt-ar-server-info.sh" >&2
    exit 1
  fi
  exit 0
fi

write_embed_block "${HITT_SH}" "${block_file}"
echo "embed-hitt-ar-server-info: updated ${HITT_SH}"
