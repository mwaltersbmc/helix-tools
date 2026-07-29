#!/usr/bin/env bash
# One-time / occasional setup for the Playback narrated-video pipeline.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/vhs-docker-lib.sh
source "$REPO_ROOT/scripts/vhs-docker-lib.sh"

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

VOICES_DIR="$REPO_ROOT/docs/videos/playback/voices"

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

echo "==> Applying playback-cli ffmpeg patch (Linux/WSL system ffmpeg) ..."
node "$REPO_ROOT/scripts/patch-playback-ffmpeg.mjs"

echo ""
echo "==> Checking external tools ..."
missing=0

if vhs_should_use_docker; then
  if vhs_docker_available; then
    echo "  ok: docker (default VHS runner for silent + narrated videos)"
  else
    missing=1
    echo "  missing: docker"
    echo "    Start Docker Desktop / Docker Engine, or use --native when rendering"
  fi
else
  if need vhs; then
    echo "  ok: vhs (--native / VHS_DOCKER=0 mode)"
  else
    missing=1
    echo "    Ubuntu/WSL2 native: docs/videos/SETUP-ubuntu-wsl.md"
  fi
fi

for cmd in ffmpeg piper; do
  if need "$cmd"; then
    echo "  ok: $cmd"
  else
    missing=1
    case "$cmd" in
      ffmpeg)
        echo "    Ubuntu/WSL2: sudo apt install ffmpeg"
        ;;
      piper)
        echo "    Ubuntu/WSL2: curl -LsSf https://astral.sh/uv/install.sh | sh && uv tool install piper-tts"
        echo "    ensure ~/.local/bin is on PATH"
        ;;
    esac
  fi
done

echo ""
echo "==> Downloading default piper voice (northern_english_male) ..."
bash "$REPO_ROOT/scripts/download-playback-voice.sh" northern_english_male

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
echo "See docs/videos/SETUP-ubuntu-wsl.md for Ubuntu/WSL2 install steps."
