#!/usr/bin/env bash
# Run VHS for a generated .tape file (Docker by default).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=scripts/vhs-docker-lib.sh
source "$REPO_ROOT/scripts/vhs-docker-lib.sh"

USE_DOCKER=""
TAPE_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --native)
      USE_DOCKER=0
      shift
      ;;
    --docker)
      USE_DOCKER=1
      shift
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      exit 1
      ;;
    *)
      TAPE_PATH="$1"
      shift
      ;;
  esac
done

if [[ -z "$TAPE_PATH" ]]; then
  echo "Usage: scripts/video/run-vhs.sh [--native] <tape-path>" >&2
  exit 1
fi

# Normalize Windows-style relative paths from Node on Win32.
TAPE_PATH="${TAPE_PATH//\\//}"

if [[ "$TAPE_PATH" =~ ^[A-Za-z]:/ ]]; then
  echo "error: expected repo-relative tape path, got Windows absolute path: $TAPE_PATH" >&2
  echo "  Re-run from WSL, or use a Node build that matches your bash environment." >&2
  exit 1
fi

if [[ "$TAPE_PATH" != /* ]]; then
  TAPE_PATH="$REPO_ROOT/$TAPE_PATH"
fi

if [[ ! -f "$TAPE_PATH" ]]; then
  echo "error: tape not found: $TAPE_PATH" >&2
  exit 1
fi

if vhs_should_use_docker; then
  vhs_ensure_docker_prereqs || exit 1
  vhs_run_docker "$TAPE_PATH" "$REPO_ROOT"
else
  if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs not on PATH (--native). Install VHS or omit --native." >&2
    exit 1
  fi
  cd "$REPO_ROOT"
  vhs "$TAPE_PATH"
fi
