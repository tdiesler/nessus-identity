#! /bin/bash
#

NDC_HOME=$(realpath "$(dirname $0)/..")
cd "${NDC_HOME}" || exit 1

KUBECTL="kubectl"

# Signals get sent to the main process, which is this script
# Use exec so that the executable becomes part of the same process

if [[ $1 == "backdoor" ]]; then

  app_selector="${2:-backdoor}"
  pod_name=$(${KUBECTL} get pods -l "app.kubernetes.io/name=$app_selector" -o jsonpath='{.items[0].metadata.name}')
  if [ -z "$pod_name" ]; then
    echo "No pod found with app selector app.kubernetes.io/name=$app_selector"
    exit 1
  fi

  echo "Exec into pod $pod_name"
  ${KUBECTL} exec -it "$pod_name" -- bash

else

  echo "Unknown: $1"

fi