#!/usr/bin/env bash
# Render narrated HITT use-case videos via playback-cli (YAML → VHS + TTS + captions).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$REPO_ROOT/docs/hitt/use-cases.json"
PLAYBACK_ROOT="$REPO_ROOT/docs/videos/playback"
OUTPUT_ROOT="$REPO_ROOT/docs/assets/videos/playback"
MODE="tape"
VALIDATE_ONLY=0
REQUESTED_IDS=()
PLAYBACK_EXTRA=()

usage() {
  cat <<'EOF'
Usage: scripts/render-playback.sh [options] [use-case-id ...]

  No arguments  — render playback tapes for use cases with video.playback.enabled
  With IDs      — render those use cases (ignores playback.enabled)

Options:
  --validate       Parse and validate tapes only (no recording)
  --vhs-only       Terminal recording only — skip TTS and caption mux
  --audit          Print timing audit after synthesis
  --audit-fix      Audit and write pause fixes back to tape.yaml
  --debug-overlay  Burn command labels into the video (timing debug)
  --mkv            Also produce MKV with embedded subtitles
  -h, --help       Show this help

Examples:
  npm run playback:render -- info-cluster-status
  ./scripts/render-playback.sh --validate info-cluster-status
  ./scripts/render-playback.sh download-hitt hitt-config-change

Requires: npm run playback:setup (Node >= 22, vhs, ffmpeg, piper, voice models)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --validate)
      VALIDATE_ONLY=1
      MODE="validate"
      shift
      ;;
    --vhs-only)
      MODE="tape"
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
