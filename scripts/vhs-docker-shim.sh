#!/usr/bin/env bash
# playback-cli spawns `vhs` on PATH — this shim runs VHS in Docker instead.
set -euo pipefail

REPO_ROOT="${HELIX_REPO_ROOT:?HELIX_REPO_ROOT must be set by render-playback.sh}"
# shellcheck source=scripts/vhs-docker-lib.sh
source "$REPO_ROOT/scripts/vhs-docker-lib.sh"

if [[ $# -lt 1 ]]; then
  echo "error: vhs shim: tape file argument required" >&2
  exit 1
fi

tape_path="$1"
shift || true

vhs_run_docker "$tape_path" "$REPO_ROOT"
