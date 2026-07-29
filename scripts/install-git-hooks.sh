#!/usr/bin/env bash
# Enable repo git hooks (.githooks/) and verify gitleaks is available.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

install_gitleaks_linux() {
  local version="${GITLEAKS_VERSION:-8.24.2}"
  local arch dest tmpdir
  case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "error: unsupported architecture for auto-install: $(uname -m)" >&2
      return 1
      ;;
  esac
  dest="${HOME}/.local/bin/gitleaks"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  echo "==> Downloading gitleaks v${version} (${arch}) to ${dest} ..."
  curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_${arch}.tar.gz" \
    -o "${tmpdir}/gitleaks.tar.gz"
  tar -xzf "${tmpdir}/gitleaks.tar.gz" -C "${tmpdir}"
  install -m 0755 "${tmpdir}/gitleaks" "${dest}"
  echo "Installed: ${dest}"
  echo "Ensure ~/.local/bin is on PATH."
}

cd "$REPO_ROOT"

chmod +x .githooks/pre-commit .githooks/pre-commit-hitt-version

echo "==> Setting git core.hooksPath to .githooks (local config) ..."
git config core.hooksPath .githooks

if command -v gitleaks >/dev/null 2>&1; then
  echo "  ok: gitleaks $(gitleaks version 2>/dev/null | head -1 || true)"
else
  echo "  missing: gitleaks"
  if [[ "${1:-}" == "--install-gitleaks" ]]; then
    install_gitleaks_linux
  else
    echo ""
    echo "Install gitleaks, then re-run this script:"
    echo "  bash scripts/install-git-hooks.sh --install-gitleaks"
    echo ""
    echo "Or install manually: https://github.com/gitleaks/gitleaks#installing"
    exit 1
  fi
fi

echo ""
echo "Git hooks enabled. Pre-commit runs:"
echo "  1. gitleaks protect --staged  (SKIP_GITLEAKS=1 to bypass)"
echo "  2. HITT build version bump when hitt/hitt.sh is staged  (SKIP_HITT_VERSION_HOOK=1 to bypass)"
echo ""
echo "Test: gitleaks detect --source . --config .gitleaks.toml --no-git"
