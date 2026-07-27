#!/bin/sh

while true; do
  numpods=$(kubectl get pods --field-selector=status.phase=Succeeded --all-namespaces 2>/dev/null | wc -l)
  if [ "$numpods" != "0" ]; then
    echo "Deleting completed pods - $numpods"
    kubectl delete pods --field-selector=status.phase=Succeeded --all-namespaces 2>/dev/null
  fi
  sleep 60
done
