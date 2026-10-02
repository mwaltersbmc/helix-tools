#!/usr/bin/env bash
#
# Set ingress class on every Ingress in a namespace. Only overwrites the
# kubernetes.io/ingress.class annotation when that key is already present.
#
# Usage:
#   bash set-ingress-class.sh -n mrw-03-is -c nginx
#   bash set-ingress-class.sh -n mrw-03-is -c nginx --dry-run

set -euo pipefail

NAMESPACE=""
INGRESS_CLASS=""
DRY_RUN=0
SKIP_CLASS_CHECK=0

if [[ -n "${KUBECTL:-}" ]]; then
  # shellcheck disable=SC2206
  KUBECTL_CMD=(${KUBECTL})
else
  KUBECTL_CMD=(kubectl)
fi

usage() {
  cat <<'EOF'
Usage: set-ingress-class.sh -n NAME -c NAME [options]

Required:
  -n, --namespace NAME   Kubernetes namespace
  -c, --class NAME       IngressClass name (annotation value to set)

Options:
  --dry-run              Print patches without applying
  --skip-class-check     Do not require an IngressClass resource named -c
  -h, --help             Show this help

Environment:
  KUBECTL                kubectl command and flags (e.g. kubectl --context prod)
EOF
}

require_arg() {
  local opt="$1"
  if [[ $# -lt 2 ]] || [[ "${2}" == -* ]]; then
    echo "Option ${opt} requires a value." >&2
    usage >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)
      require_arg "$1" "${2-}"
      NAMESPACE="$2"
      shift 2
      ;;
    -c|--class)
      require_arg "$1" "${2-}"
      INGRESS_CLASS="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --skip-class-check)
      SKIP_CLASS_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${NAMESPACE}" || -z "${INGRESS_CLASS}" ]]; then
  echo "Both -n/--namespace and -c/--class are required." >&2
  usage >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not on PATH." >&2
  exit 1
fi

ns_err=$("${KUBECTL_CMD[@]}" get namespace "${NAMESPACE}" 2>&1) || {
  if [[ "${ns_err}" == *NotFound* ]] || [[ "${ns_err}" == *"not found"* ]]; then
    echo "Namespace '${NAMESPACE}' not found." >&2
  else
    echo "Cannot read namespace '${NAMESPACE}' (check context and RBAC): ${ns_err}" >&2
  fi
  exit 1
}

if [[ "${SKIP_CLASS_CHECK}" -eq 0 ]]; then
  ic_err=$("${KUBECTL_CMD[@]}" get ingressclass "${INGRESS_CLASS}" 2>&1) || {
    if [[ "${ic_err}" == *NotFound* ]] || [[ "${ic_err}" == *"not found"* ]]; then
      echo "IngressClass '${INGRESS_CLASS}' not found in cluster." >&2
      echo "Use --skip-class-check if you only need the legacy annotation value." >&2
    else
      echo "Cannot read IngressClass '${INGRESS_CLASS}' (check context and RBAC): ${ic_err}" >&2
    fi
    exit 1
  }
fi

ingress_json=$("${KUBECTL_CMD[@]}" get ingress.networking.k8s.io -n "${NAMESPACE}" -o json 2>&1) || {
  echo "Cannot list Ingress resources in '${NAMESPACE}': ${ingress_json}" >&2
  exit 1
}

ingress_count=$(jq -r '.items | length' <<< "${ingress_json}")
if [[ "${ingress_count}" -eq 0 ]]; then
  echo "No Ingress resources in namespace '${NAMESPACE}'."
  exit 0
fi

updated=0
skipped=0
failed=0

while IFS=$'\t' read -r name annot spec_class; do
  [[ -z "${name}" ]] && continue

  if [[ -z "${annot}" ]]; then
    if [[ -n "${spec_class}" ]]; then
      echo "Skipping ingress/${name} (uses spec.ingressClassName='${spec_class}', not the legacy annotation)."
    else
      echo "Skipping ingress/${name} (no kubernetes.io/ingress.class annotation)."
    fi
    skipped=$((skipped + 1))
    continue
  fi

  verb="Updating"
  [[ "${DRY_RUN}" -eq 1 ]] && verb="Would update"
  echo "${verb} ingress/${name} (annotation was '${annot}') ..."

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if ! "${KUBECTL_CMD[@]}" annotate ingress.networking.k8s.io "${name}" -n "${NAMESPACE}" \
      --dry-run=client \
      "kubernetes.io/ingress.class=${INGRESS_CLASS}" \
      --overwrite >/dev/null; then
      failed=$((failed + 1))
      continue
    fi
  else
    if ! "${KUBECTL_CMD[@]}" annotate ingress.networking.k8s.io "${name}" -n "${NAMESPACE}" \
      "kubernetes.io/ingress.class=${INGRESS_CLASS}" \
      --overwrite; then
      failed=$((failed + 1))
      continue
    fi
  fi
  updated=$((updated + 1))
done < <(jq -r '.items[] | [.metadata.name, (.metadata.annotations["kubernetes.io/ingress.class"] // ""), (.spec.ingressClassName // "")] | @tsv' <<< "${ingress_json}")

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "Dry run complete."
  echo "Done. Would update ${updated} ingress(es), skipped ${skipped}, failed ${failed} in '${NAMESPACE}' (class '${INGRESS_CLASS}')."
else
  echo "Done. Updated ${updated} ingress(es), skipped ${skipped}, failed ${failed} in '${NAMESPACE}' (class '${INGRESS_CLASS}')."
fi

if [[ "${failed}" -gt 0 ]]; then
  exit 1
fi
