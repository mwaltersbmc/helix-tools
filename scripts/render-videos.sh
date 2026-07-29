#!/usr/bin/env bash
# Render HITT use-case terminal videos via VHS (local, on-demand).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/vhs-docker-lib.sh
source "$REPO_ROOT/scripts/vhs-docker-lib.sh"

MANIFEST="$REPO_ROOT/docs/hitt/use-cases.json"
VIDEOS_DIR="$REPO_ROOT/docs/videos"
ASSETS_DIR="$REPO_ROOT/docs/assets/videos"
USE_DOCKER=""
REQUESTED_IDS=()

usage() {
  cat <<'EOF'
Usage: scripts/render-videos.sh [options] [use-case-id ...]

  No arguments  — render every use case with video.enabled == true
  With IDs      — render only those use cases (ignores enabled flag)

Options:
  --docker      Run VHS inside the official Docker image (default)
  --native      Use native vhs on the host instead of Docker
  -h, --help    Show this help

Environment:
  VHS_DOCKER=0         Same as --native
  VHS_FORCE_NATIVE=1   Same as --native
  VHS_IMAGE            Docker image (default: ghcr.io/charmbracelet/vhs)

Examples:
  ./scripts/render-videos.sh
  ./scripts/render-videos.sh info-cluster-status
  ./scripts/render-videos.sh --native info-cluster-status

Requires: Docker (default), or native vhs + ffmpeg + ttyd with --native
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --docker)
      USE_DOCKER=1
      shift
      ;;
    --native)
      USE_DOCKER=0
      shift
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      REQUESTED_IDS+=("$1")
      shift
      ;;
  esac
done

warn_stale_ttyd() {
  if ! vhs_is_windows_like; then
    return
  fi
  if command -v tasklist >/dev/null 2>&1 && tasklist 2>/dev/null | grep -qi ttyd; then
    echo "warning: ttyd is already running; stale processes can block VHS." >&2
    echo "  taskkill //F //IM ttyd.exe" >&2
  fi
}

ensure_prereqs() {
  if vhs_should_use_docker; then
    vhs_ensure_docker_prereqs || exit 1
    return
  fi

  if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs is not installed or not on PATH (--native mode)." >&2
    echo "" >&2
    echo "Install options:" >&2
    echo "  docs/videos/SETUP-ubuntu-wsl.md  (Charm apt on Ubuntu/WSL)" >&2
    echo "  Or omit --native to use Docker (default)" >&2
    exit 1
  fi

  if vhs_is_windows_like; then
    warn_stale_ttyd
    echo "warning: native VHS on Windows/Git Bash often hangs (known ttyd issue)." >&2
    echo "  Prefer Docker (default): ./scripts/render-videos.sh $*" >&2
  fi
}

run_vhs() {
  local tape_path="$1"

  if vhs_should_use_docker; then
    vhs_run_docker "$tape_path" "$REPO_ROOT"
  else
    vhs "$tape_path"
  fi
}

resolve_tapes() {
  local ids=("${REQUESTED_IDS[@]}")

  if command -v jq >/dev/null 2>&1; then
    if ((${#ids[@]} == 0)); then
      jq -r '.useCases[] | select(.video.enabled == true) | .id + "\t" + .video.tape' "$MANIFEST"
    else
      local id tape
      for id in "${ids[@]}"; do
        tape="$(jq -r --arg id "$id" '.useCases[] | select(.id == $id) | .video.tape // empty' "$MANIFEST")"
        if [[ -z "$tape" ]]; then
          echo "error: use case not found in manifest: $id" >&2
          exit 1
        fi
        printf '%s\t%s\n' "$id" "$tape"
      done
    fi
    return 0
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: need jq or python3 to parse $MANIFEST" >&2
    exit 1
  fi

  python3 - "$MANIFEST" "${ids[@]}" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
requested = sys.argv[2:]

with open(manifest_path, encoding="utf-8") as fh:
    data = json.load(fh)

cases = {uc["id"]: uc for uc in data.get("useCases", [])}

if requested:
    for uid in requested:
        uc = cases.get(uid)
        if not uc or "video" not in uc:
            print(f"error: use case not found in manifest: {uid}", file=sys.stderr)
            sys.exit(1)
        print(f"{uid}\t{uc['video']['tape']}")
else:
    for uc in data.get("useCases", []):
        video = uc.get("video") or {}
        if video.get("enabled"):
            print(f"{uc['id']}\t{video['tape']}")
PY
}

ensure_prereqs

if [[ ! -f "$MANIFEST" ]]; then
  echo "error: manifest not found: $MANIFEST" >&2
  exit 1
fi

mapfile -t rows < <(resolve_tapes)

if ((${#rows[@]} == 0)); then
  echo "No use cases selected for rendering." >&2
  echo "Enable video.enabled in docs/hitt/use-cases.json or pass explicit IDs." >&2
  exit 1
fi

mkdir -p "$ASSETS_DIR"
cd "$REPO_ROOT"

rendered=()
for row in "${rows[@]}"; do
  id="${row%%$'\t'*}"
  tape="${row#*$'\t'}"
  tape_path="$VIDEOS_DIR/$tape"

  if [[ ! -f "$tape_path" ]]; then
    echo "error: tape file not found for $id: $tape_path" >&2
    exit 1
  fi

  echo "Rendering $id ($tape_path) ..."
  run_vhs "$tape_path"
  rendered+=("$id")
done

echo ""
echo "Rendered ${#rendered[@]} tape(s). Generated assets:"
for id in "${rendered[@]}"; do
  for ext in mp4 gif; do
    asset="$ASSETS_DIR/$id.$ext"
    if [[ -f "$asset" ]]; then
      echo "  $asset"
    fi
  done
done

echo ""
echo "Review the output, then commit docs/assets/videos/* when ready."
