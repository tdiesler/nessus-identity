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
init_opts() {
  opt_clean=false
  opt_show_help=true
  opt_run_all=false
  opt_run_test=""
}

init_opts

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      opt_clean=true
      ;;
    --help)
      init_opts
      break
      ;;
    --run-all)
      opt_run_all=true
      ;;
    --run-smoke-test)
      opt_run_test="oid4vci-1_0-issuer-happy-flow"
      ;;
    --run-test)
      [[ -z "$2" || "$2" == --* ]] && {
        echo "Missing value for --run-test"
        init_opts
        break
      }
      opt_run_test="$2"
      shift
      ;;
    *)
      echo "Unknown option: $1";
      init_opts
      break
      ;;
  esac
  shift
done

clean_plans() {
  plan_ids=$(curl -ks "${CONFORMANCE_SERVER}/api/plan" | jq -r '.data[]._id')
  for id in $plan_ids; do
    echo "Deleting: ${id}"
    curl -ks -X DELETE "${CONFORMANCE_SERVER}/api/plan/${id}"
  done
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

  ./run-test-plan.py --no-parallel "${PLAN_NAME}${PLAN_VARIANTS}:${modules}" "${CONFIG_FILE}"
}

show_help() {
  local cmd="$1"
  echo "usage: ${cmd} [--clean] [--help] [--run-all] [--run-smoke-test] [--run-test module]"
}

_activate_venv() {
  pushd "${CONFORMANCE_SCRIPTS_DIR}" > /dev/null
  source .venv/bin/activate
}

_deactivate_venv() {
  deactivate
  popd > /dev/null
}

# Optionally clean existing test plans ---------------------------------------------------------------------------------
#
if [[ ${opt_clean} == true ]]; then
  clean_plans
fi

# Run all pre-configured modules for the given test plan ---------------------------------------------------------------
#
if [[ ${opt_run_all} == true ]]; then
  _activate_venv

  run_test_modules ""

  _deactivate_venv
  exit 0
fi

# Run a single module from the given test plan -------------------------------------------------------------------------
#
if [[ -n ${opt_run_test} ]]; then
  _activate_venv

  run_test_modules "${opt_run_test}"

  _deactivate_venv
  exit 0
fi

# Show help for this script and for run-test-plan.py -------------------------------------------------------------------
#
if [[ ${opt_show_help} == true ]]; then
  show_help "$0"
  exit 0
fi
