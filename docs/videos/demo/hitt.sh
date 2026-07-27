#!/usr/bin/env bash
# Demo mock for VHS terminal recordings — not used in production HITT runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mode=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m)
      mode="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

case "$mode" in
  "info cluster")
    cat "$ROOT/fixtures/info-cluster-status.txt"
    ;;
  post-hp)
    cat <<'EOF'
HITT demo: hitt.conf not found — starting configuration wizard...

(In a real run, HITT scans the cluster and prompts for Helix Platform
namespace, Helix IS namespace, customer service, environment, and
Deployment Engine settings.)

EOF
    ;;
  *)
    echo "HITT demo: unsupported -m value: ${mode:-<none>}" >&2
    exit 1
    ;;
esac
