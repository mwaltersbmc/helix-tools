#!/usr/bin/env bash
# Download Piper ONNX voice models for playback-cli into docs/videos/playback/voices/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VOICES_DIR="$REPO_ROOT/docs/videos/playback/voices"
HF_BASE="https://huggingface.co/rhasspy/piper-voices/resolve/main"

usage() {
  cat <<'EOF'
Usage: scripts/download-playback-voice.sh [options] <voice> [voice...]

Download Piper voice model files (.onnx + .onnx.json) for use with playback-cli.
Voice names match meta.yaml "voices:" entries (e.g. alan, alba).

Options:
  -l, --list       List known voice names and whether they are already downloaded
  -f, --force      Re-download even if files already exist
  -h, --help       Show this help

Examples:
  ./scripts/download-playback-voice.sh alan
  ./scripts/download-playback-voice.sh alan alba
  npm run playback:voice -- alan

Built-in voices: alan, alba, northern_english_male, southern_english_female, aru_09
Custom voices: define in voices.yaml at repo root (model + url fields), then download by key name.

Browse samples: https://rhasspy.github.io/piper-samples/
EOF
}

# Built-in playback catalogue (same as playback-cli defaults).
builtin_voice_url() {
  case "$1" in
    alan)                  echo "en/en_GB/alan/medium" ;;
    alba)                  echo "en/en_GB/alba/medium" ;;
    northern_english_male) echo "en/en_GB/northern_english_male/medium" ;;
    southern_english_female) echo "en/en_GB/southern_english_female/low" ;;
    aru_09)                echo "en/en_GB/aru/medium" ;;
    *) return 1 ;;
  esac
}

builtin_voice_model() {
  case "$1" in
    alan)                  echo "en_GB-alan-medium" ;;
    alba)                  echo "en_GB-alba-medium" ;;
    northern_english_male) echo "en_GB-northern_english_male-medium" ;;
    southern_english_female) echo "en_GB-southern_english_female-low" ;;
    aru_09)                echo "en_GB-aru-medium" ;;
    *) return 1 ;;
  esac
}

list_builtin_voices() {
  printf '%s\n' alan alba northern_english_male southern_english_female aru_09
}

resolve_from_voices_yaml() {
  local voice="$1"
  local yaml_path="$REPO_ROOT/voices.yaml"
  [[ -f "$yaml_path" ]] || return 1

  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: voice '$voice' not in built-in catalogue; need python3 to read voices.yaml" >&2
    return 1
  fi

  python3 - "$yaml_path" "$voice" <<'PY'
import sys

try:
    import yaml
except ImportError:
    print("error: python3 PyYAML not installed (pip install pyyaml) for custom voices.yaml", file=sys.stderr)
    sys.exit(2)

path, name = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    data = yaml.safe_load(fh) or {}
entry = (data.get("voices") or {}).get(name)
if not entry or "model" not in entry or "url" not in entry:
    sys.exit(1)
print(entry["model"])
print(entry["url"])
PY
}

resolve_voice() {
  local voice="$1"
  local model url lines

  if model="$(builtin_voice_model "$voice" 2>/dev/null)"; then
    url="$(builtin_voice_url "$voice")"
    RESOLVED_MODEL="$model"
    RESOLVED_URL="$url"
    return 0
  fi

  if lines="$(resolve_from_voices_yaml "$voice" 2>/dev/null)"; then
    RESOLVED_MODEL="$(sed -n '1p' <<<"$lines")"
    RESOLVED_URL="$(sed -n '2p' <<<"$lines")"
    return 0
  fi

  echo "error: unknown voice '$voice'" >&2
  echo "  Built-in: $(list_builtin_voices | tr '\n' ' ')" >&2
  echo "  Or add '$voice' to voices.yaml at repo root (see node_modules/playback-cli/voices.example.yaml)" >&2
  return 1
}

download_voice_files() {
  local voice="$1"
  local force="${2:-0}"
  local model url base dest

  resolve_voice "$voice"
  model="$RESOLVED_MODEL"
  url="$RESOLVED_URL"
  base="${HF_BASE}/${url}"

  mkdir -p "$VOICES_DIR"
  echo "==> $voice ($model)"

  for ext in onnx "onnx.json"; do
    dest="$VOICES_DIR/${model}.${ext}"
    if [[ -f "$dest" && "$force" != "1" ]]; then
      echo "  skip (exists): $dest"
      continue
    fi
    echo "  fetching: ${model}.${ext}"
    curl -fsSL "${base}/${model}.${ext}" -o "$dest"
  done
}

list_voices_status() {
  local voice model onnx
  echo "Voice catalogue (models in $VOICES_DIR):"
  echo ""
  while read -r voice; do
    if model="$(builtin_voice_model "$voice" 2>/dev/null)"; then
      onnx="$VOICES_DIR/${model}.onnx"
      if [[ -f "$onnx" ]]; then
        echo "  $voice  ($model)  [downloaded]"
      else
        echo "  $voice  ($model)  [not downloaded]"
      fi
    fi
  done < <(list_builtin_voices)

  if [[ -f "$REPO_ROOT/voices.yaml" ]] && command -v python3 >/dev/null 2>&1; then
    python3 - "$REPO_ROOT/voices.yaml" "$VOICES_DIR" <<'PY'
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit(0)

path, voices_dir = sys.argv[1], Path(sys.argv[2])
data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
builtin = {"alan", "alba", "northern_english_male", "southern_english_female", "aru_09"}
for name, entry in sorted((data.get("voices") or {}).items()):
    if name in builtin:
        continue
    model = entry.get("model", "?")
    onnx = voices_dir / f"{model}.onnx"
    status = "[downloaded]" if onnx.is_file() else "[not downloaded]"
    print(f"  {name}  ({model})  {status}  (voices.yaml)")
PY
  fi
  echo ""
  echo "Download: ./scripts/download-playback-voice.sh <voice>"
}

FORCE=0
VOICES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -l|--list)
      list_voices_status
      exit 0
      ;;
    -f|--force)
      FORCE=1
      shift
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      VOICES+=("$1")
      shift
      ;;
  esac
done

if ((${#VOICES[@]} == 0)); then
  usage >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required" >&2
  exit 1
fi

for voice in "${VOICES[@]}"; do
  download_voice_files "$voice" "$FORCE"
done

echo ""
echo "Done. Set meta.yaml voices: [${VOICES[*]}] and re-run npm run playback:render"
