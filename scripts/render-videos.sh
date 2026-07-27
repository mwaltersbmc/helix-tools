#!/usr/bin/env bash
# Render HITT use-case terminal videos via VHS (local, on-demand).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/docs/hitt/use-cases.json"
VIDEOS_DIR="$REPO_ROOT/docs/videos"
ASSETS_DIR="$REPO_ROOT/docs/assets/videos"
VHS_IMAGE="${VHS_IMAGE:-ghcr.io/charmbracelet/vhs}"
USE_DOCKER=""
REQUESTED_IDS=()

usage() {
  cat <<'EOF'
Usage: scripts/render-videos.sh [options] [use-case-id ...]

  No arguments  — render every use case with video.enabled == true
  With IDs      — render only those use cases (ignores enabled flag)

Options:
  --docker      Run VHS inside the official Docker image (recommended on Windows)
  --native      Force native vhs even on Windows (often hangs — see README)
  -h, --help    Show this help

Environment:
  VHS_DOCKER=1         Same as --docker
  VHS_FORCE_NATIVE=1   Same as --native
  VHS_IMAGE            Docker image (default: ghcr.io/charmbracelet/vhs)

Examples:
  ./scripts/render-videos.sh
  ./scripts/render-videos.sh --docker info-cluster-status
  ./scripts/render-videos.sh download-hitt hitt-config-change

Requires: vhs + ffmpeg + ttyd (native), or Docker (recommended on Windows/Git Bash)
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

is_windows_like() {
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
  esac
  [[ "${OS:-}" == "Windows_NT" ]]
}

docker_available() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

repo_docker_mount() {
  local root="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$root" | tr '\\' '/'
  elif [[ "$root" =~ ^/[a-zA-Z]/.* ]]; then
    local drive rest
    drive="$(echo "${root:1:1}" | tr '[:lower:]' '[:upper:]')"
    rest="${root:2}"
    printf '%s:%s' "$drive" "$rest"
  else
    printf '%s' "$root"
  fi
}

should_use_docker() {
  if [[ -n "$USE_DOCKER" ]]; then
    [[ "$USE_DOCKER" == "1" ]]
    return
  fi
  if [[ "${VHS_FORCE_NATIVE:-}" == "1" ]]; then
    return 1
  fi
  if [[ "${VHS_DOCKER:-}" == "1" ]]; then
    return 0
  fi
  is_windows_like
}

warn_stale_ttyd() {
  if ! is_windows_like; then
    return
  fi
  if command -v tasklist >/dev/null 2>&1 && tasklist 2>/dev/null | grep -qi ttyd; then
    echo "warning: ttyd is already running; stale processes can block VHS." >&2
    echo "  taskkill //F //IM ttyd.exe" >&2
  fi
}

ensure_prereqs() {
  if should_use_docker; then
    if ! docker_available; then
      echo "error: Docker is required for VHS on Windows/Git Bash but is not available." >&2
      echo "" >&2
      echo "Native VHS on Windows often hangs after the Set commands (ttyd/ConPTY issue)." >&2
      echo "Options:" >&2
      echo "  1. Start Docker Desktop and re-run with --docker" >&2
      echo "  2. Run from WSL or a Linux host" >&2
      echo "  3. Set VHS_FORCE_NATIVE=1 to attempt native vhs anyway" >&2
      exit 1
    fi
    return
  fi

  if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs is not installed or not on PATH." >&2
    echo "" >&2
    echo "Install options:" >&2
    echo "  brew install vhs" >&2
    echo "  go install github.com/charmbracelet/vhs@latest" >&2
    echo "  ./scripts/render-videos.sh --docker   (uses Docker instead)" >&2
    exit 1
  fi

  if is_windows_like; then
    warn_stale_ttyd
    echo "warning: native VHS on Windows/Git Bash often hangs (known ttyd issue)." >&2
    echo "  Prefer: ./scripts/render-videos.sh --docker $*" >&2
  fi
}

run_vhs() {
  local tape_path="$1"
  local rel_tape="${tape_path#$REPO_ROOT/}"

  if should_use_docker; then
    local mount
    mount="$(repo_docker_mount "$REPO_ROOT")"
    echo "Using Docker ($VHS_IMAGE) with mount $mount -> /vhs"
    docker run --rm \
      -v "${mount}:/vhs" \
      -w /vhs \
      "$VHS_IMAGE" \
      "$rel_tape"
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
