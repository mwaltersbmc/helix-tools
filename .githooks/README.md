# Git hooks

This repository ships hooks under `.githooks/`. Enable them once per clone:

```bash
bash scripts/install-git-hooks.sh
```

That sets `git config core.hooksPath .githooks` (local to the clone) and checks that **gitleaks** is on `PATH`.

Install gitleaks automatically (Linux/WSL x64/arm64 → `~/.local/bin`):

```bash
bash scripts/install-git-hooks.sh --install-gitleaks
export PATH="$HOME/.local/bin:$PATH"
```

## Pre-commit

| Step | Script | Skip |
|------|--------|------|
| Secret scan (staged diff only) | `gitleaks protect --staged` | `SKIP_GITLEAKS=1 git commit ...` |
| HITT `HITT_BUILD_VERSION` bump when `hitt/hitt.sh` is staged | `pre-commit-hitt-version` | `SKIP_HITT_VERSION_HOOK=1 git commit ...` |

Configuration: [`.gitleaks.toml`](../.gitleaks.toml) (extends gitleaks default rules + repo allowlists for BMC doc defaults).

## Manual scans

```bash
# Staged changes only (same as pre-commit)
gitleaks protect --staged --config .gitleaks.toml --verbose --redact

# Full working tree (includes untracked)
gitleaks detect --source . --config .gitleaks.toml --no-git

# Full git history
gitleaks detect --source . --config .gitleaks.toml
```
