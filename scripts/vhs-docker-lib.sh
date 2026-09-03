# Shared VHS Docker helpers for scripts/video/run-vhs.sh.
# Source this file; do not execute directly.

VHS_IMAGE="${VHS_IMAGE:-ghcr.io/charmbracelet/vhs}"

vhs_is_windows_like() {
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) return 0 ;;
  esac
  [[ "${OS:-}" == "Windows_NT" ]]
}

vhs_docker_available() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

vhs_repo_docker_mount() {
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

# Caller may set USE_DOCKER=0|1 before calling. Default: Docker on.
vhs_should_use_docker() {
  if [[ "${USE_DOCKER:-}" == "0" ]]; then
    return 1
  fi
  if [[ "${VHS_FORCE_NATIVE:-}" == "1" || "${VHS_DOCKER:-}" == "0" ]]; then
    return 1
  fi
  return 0
}

vhs_tape_repo_relative() {
  local tape_path="$1"
  local repo_root="$2"
  if [[ "$tape_path" == "$repo_root"/* ]]; then
    printf '%s' "${tape_path#"$repo_root"/}"
  elif [[ "$tape_path" != /* ]]; then
    printf '%s' "$tape_path"
  else
    echo "error: tape path is outside repo root ($repo_root): $tape_path" >&2
    return 1
  fi
}

vhs_run_docker() {
  local tape_path="$1"
  local repo_root="$2"
  local rel_tape mount

  rel_tape="$(vhs_tape_repo_relative "$tape_path" "$repo_root")" || return 1
  mount="$(vhs_repo_docker_mount "$repo_root")"
  echo "Using Docker ($VHS_IMAGE) with mount $mount -> /vhs"
  docker run --rm \
    -v "${mount}:/vhs" \
    -w /vhs \
    "$VHS_IMAGE" \
    "$rel_tape"
}

vhs_ensure_docker_prereqs() {
  if ! vhs_docker_available; then
    echo "error: Docker is required (default mode) but is not available." >&2
    echo "" >&2
    echo "Options:" >&2
    echo "  1. Start Docker Desktop / Docker Engine and re-run" >&2
    echo "  2. Use native VHS: pass --native (or VHS_DOCKER=0)" >&2
    return 1
  fi
}
