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
KUBECTL="${KUBECTL:-kubectl}"

usage() {
  cat <<'EOF'
Usage: set-ingress-class.sh -n NAME -c NAME [options]

Required:
  -n, --namespace NAME   Kubernetes namespace
  -c, --class NAME       IngressClass name

Options:
  --dry-run              Print patches without applying
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)
      NAMESPACE="${2:?}"
      shift 2
      ;;
    -c|--class)
      INGRESS_CLASS="${2:?}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
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

if ! "${KUBECTL}" get namespace "${NAMESPACE}" >/dev/null 2>&1; then
  echo "Namespace '${NAMESPACE}' not found." >&2
  exit 1
fi

if ! "${KUBECTL}" get ingressclass "${INGRESS_CLASS}" >/dev/null 2>&1; then
  echo "IngressClass '${INGRESS_CLASS}' not found in cluster." >&2
  exit 1
fi

mapfile -t ingresses < <("${KUBECTL}" get ingress -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

if [[ ${#ingresses[@]} -eq 0 ]]; then
  echo "No Ingress resources in namespace '${NAMESPACE}'."
  exit 0
fi

annotate_args=()
if [[ "${DRY_RUN}" -eq 1 ]]; then
  annotate_args+=(--dry-run=client)
fi

updated=0
skipped=0

for name in "${ingresses[@]}"; do
  has_annot_class=$("${KUBECTL}" get ingress "${name}" -n "${NAMESPACE}" \
    -o jsonpath='{.metadata.annotations.kubernetes\.io/ingress\.class}' 2>/dev/null || true)

  if [[ -z "${has_annot_class}" ]]; then
    echo "Skipping ingress/${name} (no kubernetes.io/ingress.class annotation)."
    skipped=$((skipped + 1))
    continue
  fi

  echo "Updating ingress/${name} (annotation was '${has_annot_class}') ..."
  "${KUBECTL}" annotate ingress "${name}" -n "${NAMESPACE}" "${annotate_args[@]}" \
    "kubernetes.io/ingress.class=${INGRESS_CLASS}" \
    --overwrite
  updated=$((updated + 1))
done

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "Dry run complete."
fi
echo "Done. Updated ${updated} ingress(es), skipped ${skipped} in '${NAMESPACE}' (class '${INGRESS_CLASS}')."
