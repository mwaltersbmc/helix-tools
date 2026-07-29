#!/usr/bin/env bash
# Print (or optionally install) dependencies for Ubuntu 24.04 LTS on WSL2.
# Run inside WSL: bash scripts/install-ubuntu-wsl-deps.sh [--install]
set -euo pipefail

INSTALL=0
if [[ "${1:-}" == "--install" ]]; then
  INSTALL=1
fi

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null
}

need_sudo() {
  if ! command -v sudo >/dev/null 2>&1; then
    echo "error: sudo is required for --install" >&2
    exit 1
  fi
}

install_ttyd_user() {
  local dest="$HOME/.local/bin/ttyd"
  mkdir -p "$HOME/.local/bin"
  if [[ -x "$dest" ]]; then
    echo "  ok: ttyd ($dest)"
    return 0
  fi
  echo "  installing ttyd to $dest ..."
  curl -fsSL -o "$dest" \
    https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64
  chmod +x "$dest"
}

install_google_chrome() {
  if command -v google-chrome-stable >/dev/null 2>&1; then
    echo "  ok: google-chrome-stable"
    return 0
  fi
  echo "  installing Google Chrome (.deb from Google — no Snap) ..."
  local deb="/tmp/google-chrome.deb"
  curl -fsSL -o "$deb" \
    https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
  sudo apt install -y "$deb"
  rm -f "$deb"
}

ensure_path_hint() {
  if [[ ":${PATH}:" != *":${HOME}/.local/bin:"* ]]; then
    echo ""
    echo "Add to ~/.bashrc:"
    echo '  export PATH="$HOME/.local/bin:$PATH"'
  fi
}

echo "HITT video pipeline — Ubuntu / WSL2 dependency check"
is_wsl && echo "(detected WSL)"
echo ""

if ((INSTALL)); then
  need_sudo
  echo "==> apt packages (sudo) ..."
  sudo apt update
  sudo apt install -y curl ca-certificates gnupg jq ffmpeg git bash
  echo ""
  echo "==> Google Chrome for VHS (official .deb — no Snap) ..."
  install_google_chrome
  echo ""
  echo "==> Node.js 22 (NodeSource) ..."
  if ! node --version 2>/dev/null | grep -qE '^v2[2-9]|^v[3-9]'; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt install -y nodejs
  else
    echo "  ok: node $(node --version)"
  fi
  echo ""
  echo "==> VHS (Charm apt) ..."
  if ! command -v vhs >/dev/null 2>&1; then
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
    sudo apt update
    sudo apt install -y vhs
  else
    echo "  ok: vhs"
  fi
  echo ""
  echo "==> ttyd (user install) ..."
  install_ttyd_user
  echo ""
  echo "==> uv + piper-tts (user install) ..."
  if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # shellcheck disable=SC1091
    [[ -f "$HOME/.local/bin/env" ]] && source "$HOME/.local/bin/env"
  fi
  if command -v uv >/dev/null 2>&1; then
    uv tool install piper-tts
  else
    echo "  warning: uv install failed; run: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  fi
  ensure_path_hint
  echo ""
  echo "System packages installed. Next from repo root:"
  echo "  npm install && npm run playback:setup"
  exit 0
fi

cat <<'EOF'
Manual setup (recommended first read):
  docs/videos/SETUP-ubuntu-wsl.md

Quick install (Ubuntu 24.04 in WSL2):
  bash scripts/install-ubuntu-wsl-deps.sh --install
  cd ~/dev/github/helix-tools
  npm install && npm run playback:setup

Or install step by step:

  sudo apt update
  sudo apt install -y curl ca-certificates gnupg jq ffmpeg git bash

  # Google Chrome (.deb — do NOT use apt install chromium-browser; that pulls Snap)
  curl -fsSL -o /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
  sudo apt install -y /tmp/google-chrome.deb
  rm -f /tmp/google-chrome.deb

  # Node.js 22+
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt install -y nodejs

  # VHS
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
  echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
  sudo apt update && sudo apt install -y vhs

  # ttyd (user-local)
  mkdir -p ~/.local/bin
  curl -fsSL -o ~/.local/bin/ttyd https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64
  chmod +x ~/.local/bin/ttyd
  export PATH="$HOME/.local/bin:$PATH"

  # piper
  curl -LsSf https://astral.sh/uv/install.sh | sh
  source "$HOME/.local/bin/env"
  uv tool install piper-tts

EOF

missing=0
for cmd in node npm ffmpeg vhs; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "ok: $cmd"
  else
    if [[ "$cmd" == "vhs" ]] && docker info >/dev/null 2>&1; then
      echo "optional: vhs (not needed when Docker is default)"
    else
      echo "missing: $cmd"
      missing=1
    fi
  fi
done
if command -v ttyd >/dev/null 2>&1 || [[ -x "$HOME/.local/bin/ttyd" ]]; then
  echo "ok: ttyd"
else
  echo "missing: ttyd"
  missing=1
fi
if command -v piper >/dev/null 2>&1 || [[ -x "$HOME/.local/bin/piper" ]]; then
  echo "ok: piper"
else
  echo "missing: piper"
  missing=1
fi
if command -v google-chrome-stable >/dev/null 2>&1; then
  echo "ok: google-chrome-stable"
else
  echo "optional: google-chrome-stable (only for --native VHS)"
fi
if docker info >/dev/null 2>&1; then
  echo "ok: docker"
else
  echo "missing: docker (default for silent + narrated VHS; start Docker Desktop or install Docker Engine)"
  missing=1
fi

if ((missing)); then
  echo ""
  echo "Run: bash scripts/install-ubuntu-wsl-deps.sh --install"
  exit 1
fi

echo ""
echo "Dependencies look good. Run: npm run playback:setup"
