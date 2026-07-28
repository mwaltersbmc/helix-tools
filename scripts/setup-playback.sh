#!/usr/bin/env bash
# One-time / occasional setup for the Playback narrated-video pipeline.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VOICES_DIR="$REPO_ROOT/docs/videos/playback/voices"
VOICE_BASE="https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_GB/northern_english_male/medium"
MODEL="en_GB-northern_english_male-medium"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    return 1
  fi
}

echo "==> Installing Node dependencies (playback-cli) ..."
cd "$REPO_ROOT"
if command -v npm >/dev/null 2>&1; then
  npm install --no-fund --no-audit
else
  echo "error: npm is required (Node.js >= 22)." >&2
  exit 1
fi

echo ""
echo "==> Checking external tools ..."
missing=0
for cmd in vhs ffmpeg piper; do
  if need "$cmd"; then
    echo "  ok: $cmd"
  else
    missing=1
    case "$cmd" in
      vhs) echo "    install: brew install vhs  OR  go install github.com/charmbracelet/vhs@latest" ;;
      ffmpeg) echo "    install: apt install ffmpeg  OR  brew install ffmpeg" ;;
      piper) echo "    install: uv tool install piper-tts  OR  pip install piper-tts" ;;
    esac
  fi
done

echo ""
echo "==> Downloading default piper voice (northern_english_male) ..."
mkdir -p "$VOICES_DIR"
for ext in onnx "onnx.json"; do
  dest="$VOICES_DIR/${MODEL}.${ext}"
  if [[ -f "$dest" ]]; then
    echo "  skip (exists): $dest"
  else
    echo "  fetching: ${MODEL}.${ext}"
    curl -fsSL "${VOICE_BASE}/${MODEL}.${ext}" -o "$dest"
  fi
done

echo ""
if ((missing)); then
  echo "Setup incomplete — install missing tools above, then re-run:" >&2
  echo "  npm run playback:setup" >&2
  exit 1
fi

echo "Playback setup complete."
echo ""
echo "Next steps:"
echo "  npm run playback:validate -- info-cluster-status"
echo "  npm run playback:render -- info-cluster-status"
echo ""
echo "See docs/videos/README.md for full usage."
