#!/usr/bin/env bash

SCRIPT_DIR=$(realpath "$(dirname "$0")")

CONFORMANCE_DIR=$(realpath "${SCRIPT_DIR}/../../conformance-suite")
CONFORMANCE_SCRIPTS_DIR="${CONFORMANCE_DIR}/scripts"

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

# Default target if not set
: "${TARGET:=proxy}"

echo "OpenID Conformance Suite target: $TARGET"
case "$TARGET" in
  proxy)
    CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443"
    ;;
  *)
    echo "Unsupported target: $TARGET"
    exit 1
    ;;
esac

CONFIG_FILE="${SCRIPT_DIR}/../docs/keycloak-openid-conformance-config.json"
PLAN_NAME="oid4vci-1_0-issuer-haip-test-plan"
PLAN_VARIANTS="[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]"

## Parse args
#
opt_clean="false"
opt_run_all="false"
opt_run_test=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --clean)
      opt_clean="true"
      shift
      ;;
    --run-all)
      opt_run_all="true"
      shift
      ;;
    --run-test)
      opt_run_test="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

clean_plans() {
  plan_ids=$(curl -ks "${CONFORMANCE_SERVER}/api/plan" | jq -r '.data[]._id')
  for id in $plan_ids; do
    echo "Deleting: ${id}"
    curl -ks -X DELETE "${CONFORMANCE_SERVER}/api/plan/${id}"
  done
}

show_help() {
  _activate_venv
  ./run-test-plan.py -h
  _deactivate_venv
}

run_test_modules() {
  local modules="$1"

  if [[ -z "${modules}" ]]; then
    modules=$(curl -ks "${CONFORMANCE_SERVER}/api/plan/info/${PLAN_NAME}" | jq -r '.modules[].testModule')
  fi

  echo "Modules for test plan ${PLAN_NAME}"
  for mod in ${modules}; do
    printf " - %s\n" "$mod"
  done
  modules=$(printf "%s\n" "${modules}" | paste -sd "," -)

  ./run-test-plan.py --no-parallel --verbose "${PLAN_NAME}${PLAN_VARIANTS}:${modules}" "${CONFIG_FILE}"
}

_activate_venv() {
  pushd "${CONFORMANCE_SCRIPTS_DIR}" > /dev/null
  source .venv/bin/activate
}

_deactivate_venv() {
  deactivate
  popd > /dev/null
}

if [[ ${opt_clean} == "true" ]]; then
  clean_plans
fi

if [[ ${opt_run_all} == "true" ]]; then
  _activate_venv

  run_test_modules ""

  _deactivate_venv
  exit 0
fi

if [[ -n ${opt_run_test} ]]; then
  _activate_venv

  run_test_modules "${opt_run_test}"

  _deactivate_venv
  exit 0
fi

# show_help