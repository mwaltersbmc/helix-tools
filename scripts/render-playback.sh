#!/usr/bin/env bash
# Render narrated HITT use-case videos via playback-cli (YAML → VHS + TTS + captions).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/vhs-docker-lib.sh
source "$REPO_ROOT/scripts/vhs-docker-lib.sh"

USE_DOCKER=""

# npm run often uses a minimal PATH; piper from `uv tool install` lives in ~/.local/bin.
ensure_playback_path() {
  local dir
  for dir in "${HOME}/.local/bin" "${HOME}/.cargo/bin" "/usr/local/bin"; do
    if [[ -d "$dir" && ":${PATH}:" != *":${dir}:"* ]]; then
      PATH="${dir}:${PATH}"
    fi
  done
  export PATH
}
ensure_playback_path

# Optional explicit ffmpeg dir for patched playback-cli (see scripts/patch-playback-ffmpeg.mjs).
ensure_playback_ffmpeg() {
  local ffmpeg ffprobe shim_dir
  ffmpeg="$(command -v ffmpeg || true)"
  ffprobe="$(command -v ffprobe || true)"
  if [[ -z "$ffmpeg" || -z "$ffprobe" ]]; then
    echo "error: ffmpeg and ffprobe are required on PATH." >&2
    exit 1
  fi
  shim_dir="$REPO_ROOT/.playback/ffmpeg-bin"
  mkdir -p "$shim_dir"
  ln -sf "$ffmpeg" "$shim_dir/ffmpeg"
  ln -sf "$ffprobe" "$shim_dir/ffprobe"
  export PLAYBACK_FFMPEG_BIN="$shim_dir"
}

ensure_vhs_prereqs() {
  if vhs_should_use_docker; then
    vhs_ensure_docker_prereqs || exit 1
    vhs_install_docker_shim "$REPO_ROOT"
    echo "VHS recording: Docker ($VHS_IMAGE) via playback-cli shim"
    return
  fi

  if ! command -v vhs >/dev/null 2>&1; then
    echo "error: vhs is not installed or not on PATH (--native mode)." >&2
    echo "  docs/videos/SETUP-ubuntu-wsl.md  or omit --native to use Docker (default)" >&2
    exit 1
  fi
  echo "VHS recording: native vhs on host"
}

MANIFEST="$REPO_ROOT/docs/hitt/use-cases.json"
PLAYBACK_ROOT="$REPO_ROOT/docs/videos/playback"
OUTPUT_ROOT="$REPO_ROOT/docs/assets/videos/playback"
VALIDATE_ONLY=0
REQUESTED_IDS=()
PLAYBACK_EXTRA=()

usage() {
  cat <<'EOF'
Usage: scripts/render-playback.sh [options] [use-case-id ...]

  No arguments  — render playback tapes for use cases with video.playback.enabled
  With IDs      — render those use cases (ignores playback.enabled)

Options:
  --docker      Run VHS inside Docker (default; playback-cli uses a PATH shim)
  --native      Use native vhs on the host for terminal recording
  --validate       Parse and validate tapes only (no recording)
  --vhs-only       Terminal recording only — skip TTS and caption mux
  --audit          Print timing audit after synthesis
  --audit-fix      Audit and write pause fixes back to tape.yaml
  --debug-overlay  Burn command labels into the video (timing debug)
  --mkv            Also produce MKV with embedded subtitles
  -h, --help       Show this help

Environment:
  VHS_DOCKER=0         Same as --native
  VHS_FORCE_NATIVE=1   Same as --native
  VHS_IMAGE            Docker image (default: ghcr.io/charmbracelet/vhs)

Examples:
  npm run playback:render -- info-cluster-status
  ./scripts/render-playback.sh --validate info-cluster-status
  ./scripts/render-playback.sh --native download-hitt

Requires: Docker (default for VHS), ffmpeg, piper, voice models; --native also needs host vhs
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
    --validate)
      VALIDATE_ONLY=1
      shift
      ;;
    --vhs-only)
      PLAYBACK_EXTRA+=(--vhs-only)
      shift
      ;;
    --audit)
      PLAYBACK_EXTRA+=(--audit)
      shift
      ;;
    --audit-fix)
      PLAYBACK_EXTRA+=(--audit-fix)
      shift
      ;;
    --debug-overlay)
      PLAYBACK_EXTRA+=(--debug-overlay)
      shift
      ;;
    --mkv)
      PLAYBACK_EXTRA+=(--mkv)
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

if [[ ! -f "$MANIFEST" ]]; then
  echo "error: manifest not found: $MANIFEST" >&2
  exit 1
fi

if [[ ! -x "$REPO_ROOT/node_modules/.bin/playback" ]] && ! command -v playback >/dev/null 2>&1; then
  echo "error: playback-cli not installed. Run: npm run playback:setup" >&2
  exit 1
fi

if (( ! VALIDATE_ONLY )); then
  ensure_vhs_prereqs
fi

if [[ "${PLAYBACK_SKIP_PIPER_CHECK:-}" != "1" ]] && (( ! VALIDATE_ONLY )) && [[ " ${PLAYBACK_EXTRA[*]} " != *" --vhs-only "* ]]; then
  if ! command -v piper >/dev/null 2>&1; then
    echo "error: piper not on PATH (checked after ~/.local/bin)." >&2
    echo "  uv tool install piper-tts" >&2
    echo "  Or export PATH=\"\$HOME/.local/bin:\$PATH\" before npm run" >&2
    exit 1
  fi
  ensure_playback_ffmpeg
fi

playback_cmd() {
  if [[ -x "$REPO_ROOT/node_modules/.bin/playback" ]]; then
    "$REPO_ROOT/node_modules/.bin/playback" "$@"
  else
    playback "$@"
  fi
}

resolve_playback_rows() {
  local ids=("${REQUESTED_IDS[@]}")

  if command -v jq >/dev/null 2>&1; then
    if ((${#ids[@]} == 0)); then
      jq -r '.useCases[] | select(.video.playback.enabled == true) | .id + "\t" + .video.playback.dir' "$MANIFEST"
    else
      local id dir
      for id in "${ids[@]}"; do
        dir="$(jq -r --arg id "$id" '.useCases[] | select(.id == $id) | .video.playback.dir // empty' "$MANIFEST")"
        if [[ -z "$dir" ]]; then
          echo "error: use case not found or missing video.playback.dir: $id" >&2
          exit 1
        fi
        printf '%s\t%s\n' "$id" "$dir"
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
        playback = (uc or {}).get("video", {}).get("playback") or {}
        if not uc or not playback.get("dir"):
            print(f"error: use case not found or missing video.playback.dir: {uid}", file=sys.stderr)
            sys.exit(1)
        print(f"{uid}\t{playback['dir']}")
else:
    for uc in data.get("useCases", []):
        playback = uc.get("video", {}).get("playback") or {}
        if playback.get("enabled"):
            print(f"{uc['id']}\t{playback['dir']}")
PY
}

mapfile -t rows < <(resolve_playback_rows)

if ((${#rows[@]} == 0)); then
  echo "No playback use cases selected." >&2
  echo "Set video.playback.enabled in docs/hitt/use-cases.json or pass explicit IDs." >&2
  exit 1
fi

cd "$REPO_ROOT"
rendered=()

for row in "${rows[@]}"; do
  id="${row%%$'\t'*}"
  dir="${row#*$'\t'}"
  tape_dir="$PLAYBACK_ROOT/$dir"

  if [[ ! -f "$tape_dir/tape.yaml" ]]; then
    echo "error: missing tape.yaml for $id: $tape_dir/tape.yaml" >&2
    echo "  Copy docs/videos/playback/_template/ to docs/videos/playback/$dir/ and edit." >&2
    exit 1
  fi
  if [[ ! -f "$tape_dir/meta.yaml" ]]; then
    echo "error: missing meta.yaml for $id: $tape_dir/meta.yaml" >&2
    exit 1
  fi

  rel_tape_dir="docs/videos/playback/$dir"

  if ((VALIDATE_ONLY)); then
    echo "Validating $id ($rel_tape_dir) ..."
    playback_cmd validate "$rel_tape_dir"
  else
    echo "Rendering playback $id ($rel_tape_dir) ..."
    playback_cmd tape "$rel_tape_dir" "${PLAYBACK_EXTRA[@]}"
  fi
  rendered+=("$id")
done

echo ""
if ((VALIDATE_ONLY)); then
  echo "Validated ${#rendered[@]} playback tape(s)."
  exit 0
fi

echo "Rendered ${#rendered[@]} playback tape(s). Output under docs/assets/videos/playback/:"
for id in "${rendered[@]}"; do
  out_dir="$OUTPUT_ROOT/$id"
  if [[ -d "$out_dir" ]]; then
    find "$out_dir" -maxdepth 1 -type f \( -name '*.mp4' -o -name '*.gif' -o -name '*.vtt' -o -name '*.srt' \) -print 2>/dev/null | sort | sed 's|^|  |'
  fi
done

echo ""
echo "Optional: npx playback-tui docs/videos/playback/<id>  (timing editor, install separately)"
echo "Review output, then commit assets when satisfied (docs/assets/ is gitignored by default)."
