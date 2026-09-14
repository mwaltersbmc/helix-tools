#!/usr/bin/env bash
# Embed docs/hitt/use-cases.json into hitt/hitt.sh as HITT_USE_CASES_JSON (heredoc).
# Strips the "video" key from each use case. Used by pre-commit and CI.
#
# Usage:
#   bash scripts/embed-hitt-use-cases.sh          # update hitt/hitt.sh in place
#   bash scripts/embed-hitt-use-cases.sh --check  # exit 1 if embed is stale
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USE_CASES_JSON="${ROOT}/docs/hitt/use-cases.json"
HITT_SH="${ROOT}/hitt/hitt.sh"
BEGIN_MARKER='# BEGIN HITT_USE_CASES_JSON'
END_MARKER='# END HITT_USE_CASES_JSON'
CHECK_ONLY=0

if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--check]" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "embed-hitt-use-cases: jq is required but not on PATH." >&2
  exit 1
fi

[[ -f "${USE_CASES_JSON}" ]] || {
  echo "embed-hitt-use-cases: missing ${USE_CASES_JSON}" >&2
  exit 1
}
[[ -f "${HITT_SH}" ]] || {
  echo "embed-hitt-use-cases: missing ${HITT_SH}" >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

filtered_json="${tmp_dir}/use-cases-no-video.json"
block_file="${tmp_dir}/embed-block.txt"
current_block="${tmp_dir}/current-block.txt"

jq '.useCases |= map(del(.video))' "${USE_CASES_JSON}" > "${filtered_json}"
jq -e '.topics and .useCases' "${filtered_json}" >/dev/null

{
  printf '%s\n' "${BEGIN_MARKER}"
  printf '%s\n' "read -r -d '' HITT_USE_CASES_JSON <<'HITT_USE_CASES_JSON_EOF' || true"
  cat "${filtered_json}"
  printf '%s\n' "HITT_USE_CASES_JSON_EOF"
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
      $0 == "ALL_MSGS_JSON_EOF" {
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
    echo "embed-hitt-use-cases: ${HITT_SH} is missing ${BEGIN_MARKER}" >&2
    exit 1
  fi
  extract_embed_block "${HITT_SH}" "${current_block}"
  if ! diff -u "${current_block}" "${block_file}"; then
    echo "embed-hitt-use-cases: embedded use cases are out of date. Run: bash scripts/embed-hitt-use-cases.sh" >&2
    exit 1
  fi
  exit 0
fi

write_embed_block "${HITT_SH}" "${block_file}"
echo "embed-hitt-use-cases: updated ${HITT_SH}"
