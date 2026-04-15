#!/usr/bin/env bash

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

SCRIPT_DIR=$(realpath "$(dirname "$0")")

CONFORMANCE_DIR=$(realpath "${SCRIPT_DIR}/../../conformance-suite")
CONFORMANCE_SCRIPTS_DIR="${CONFORMANCE_DIR}/scripts"

DEFAULT_CONFIG_FILE="${SCRIPT_DIR}/config/keycloak-openid-config.json"
DEFAULT_FAILURES_FILE="${SCRIPT_DIR}/config/keycloak-openid-failures.json"
DEFAULT_SKIPS_FILE="${SCRIPT_DIR}/config/keycloak-openid-skips.json"
DEFAULT_FILTERS_FILE="${SCRIPT_DIR}/config/keycloak-openid-filters.json"

PLAN_NAME="oid4vci-1_0-issuer-haip-test-plan"
DEFAULT_VARIANTS="[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]"

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

## Parse args
#
init_opts() {
  opt_clean=false
  opt_show_help=false
  opt_show_modules=false
  opt_run_all=false
  opt_run_config=""
  opt_run_module=""
  opt_run_profile=""
}

init_opts

show_help() {
  echo "usage: $0 [--clean] [--help] [--run-all] [--run-test module] [--run-profile name] [--show-modules]"
  echo ""
  echo "  --clean           Cleans existing test plans from the database"
  echo "  --run-all         Run the default profile and all other"
  echo "  --run-test        Run a single test module"
  echo "  --run-profile     Run the given test profile"
  echo "  --show-modules    Show effective test modules"
  echo ""
  echo "  Profiles"
  echo "    - default       Run the default profile"
  echo "    - attestation   Uses proof type 'attestation' instead of 'jwt'"
  echo ""
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      opt_clean=true
      ;;
    --help)
      opt_show_help=true
      break
      ;;
    --show-modules)
      opt_show_modules=true
      break
      ;;
    --run-all)
      opt_run_all=true
      ;;
    --run-test)
      if [[ -n "${2-}" && "${2-}" != --* ]]; then
        opt_run_module="$2"
        shift
      else
        opt_run_module="oid4vci-1_0-issuer-happy-flow"
      fi
      if [[ -n "${2-}" && "${2-}" != --* ]]; then
        opt_run_config="$2"
        shift
      fi
      ;;
    --run-profile)
      if [[ -z "${2-}" ]]; then
        echo "Requires a profile name" >&2
        exit 1
      fi
      opt_run_profile="$2"
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

if [[ -n "${opt_run_module}" && -n "${opt_run_profile}" ]]; then
  echo "Cannot specify both: --run-test AND --run-profile" >&2
  exit 1
fi

source "${SCRIPT_DIR}/oid4vci-functions-keycloak.sh"

# Remove existing test plans
#
clean_plans() {
  plan_ids=$(curl -ks "${CONFORMANCE_SERVER}/api/plan" | jq -r '.data[]._id')
  for id in $plan_ids; do
    echo "Deleting: ${id}"
    curl -ks -X DELETE "${CONFORMANCE_SERVER}/api/plan/${id}"
  done
}

# Run test modules
#
run_modules() {
  local modules="$1"
  local config="$2"

  local failures="${DEFAULT_FAILURES_FILE}"
  local skips="${DEFAULT_SKIPS_FILE}"

  if [[ -z "${modules}" ]]; then
    modules=$(printf "%s\n" "$(_get_effective_modules)" | paste -sd "," -)

    echo "Filtered modules for test plan ${PLAN_NAME}"
    for mod in $(_get_filtered_modules); do
      printf " - %s\n" "$mod"
    done
  else
    failures=""
    skips=""
  fi

  _run_test_modules "${DEFAULT_VARIANTS}" "${modules}" "${failures}" "${skips}" "${config}"
}

# Run the default profile
#
run_default_profile() {
  echo "Run profile: default";
  run_modules "" "${DEFAULT_CONFIG_FILE}"
}

# Run a profile 'attestation'
#
run_profile_attestation() {
  echo "Run profile: attestation";

  modules="oid4vci-1_0-issuer-fail-invalid-key-attestation-signature"
  config="${SCRIPT_DIR}/config/.keycloak-openid-config-attestation.json"

  # Transform the config
  jq '.vci.credential_proof_type_hint = "attestation"' "${DEFAULT_CONFIG_FILE}" > "${config}"

  _run_test_modules "${DEFAULT_VARIANTS}" "${modules}" "" "" "${config}"
}

# Show effective test modules
#
show_modules() {
  effective_modules=$(_get_effective_modules)
  filtered_modules=$(_get_filtered_modules)

  echo "Modules for test plan ${PLAN_NAME}"
  for mod in ${effective_modules}; do
    printf " - %s\n" "$mod"
  done

  echo "Filtered modules for test plan ${PLAN_NAME}"
  for mod in ${filtered_modules}; do
    printf " - %s\n" "$mod"
  done
}

_activate_venv() {
  pushd "${CONFORMANCE_SCRIPTS_DIR}" > /dev/null
  source .venv/bin/activate
}

_deactivate_venv() {
  deactivate
  popd > /dev/null
}

_get_effective_modules() {
  filtered_modules=$(_get_filtered_modules)
  while IFS= read -r mod; do
    if ! printf "%s\n" "${filtered_modules}" | grep -F -x -q "$mod"; then
      printf "%s\n" "$mod"
    fi
  done <<< "$(_get_modules)"
}

_get_filtered_modules() {
  jq -r '.[]."test-name"' "${DEFAULT_FILTERS_FILE}"
}

_get_modules() {
  curl -ks "${CONFORMANCE_SERVER}/api/plan/info/${PLAN_NAME}" | jq -r '.modules[].testModule'
}

_run_test_modules() {
  local variants="$1"
  local modules="$2"
  local failures="$3"
  local skips="$4"
  local config="$5"

  local cmd_args=(--no-parallel --verbose)

  if [[ -n "${failures}" ]]; then
    cmd_args+=(--expected-failures-file "${failures}")
  fi

  if [[ -n "${skips}" ]]; then
    cmd_args+=(--expected-skips-file "${skips}")
  fi

  echo "./run-test-plan.py ${cmd_args[*]} ${PLAN_NAME}${variants}:${modules} ${config}"
  ./run-test-plan.py "${cmd_args[@]}" "${PLAN_NAME}${variants}:${modules}" "${config}"
}

# Optionally clean existing test plans ---------------------------------------------------------------------------------
#
if [[ ${opt_clean} == true ]]; then
  clean_plans
fi

# Optionally show pre-configured modules for the given test plan -------------------------------------------------------
#
if [[ ${opt_show_modules} == true ]]; then
  _activate_venv
  show_modules
  _deactivate_venv
  exit 0
fi

# Run all pre-configured modules for the given test plan ---------------------------------------------------------------
#
if [[ ${opt_run_all} == true ]]; then
  _activate_venv
  run_profile_attestation
  run_default_profile
  _deactivate_venv
  exit 0
fi

# Run a single module from the given test plan -------------------------------------------------------------------------
#
if [[ -n ${opt_run_module} ]]; then
  _activate_venv
  run_modules "${opt_run_module}" "${opt_run_config:-$DEFAULT_CONFIG_FILE}"
  _deactivate_venv
  exit 0
fi

# Run a given test profile ---------------------------------------------------------------------------------------------
#
if [[ -n ${opt_run_profile} ]]; then
  _activate_venv
  case "$opt_run_profile" in
    attestation)
      run_profile_attestation
      ;;
    default)
      run_default_profile
      ;;
    *)
      echo "Unknown profile: $opt_run_profile";
      show_help
      exit 1
      ;;
  esac
  _deactivate_venv
  exit 0
fi

# Show help for this script --------------------------------------------------------------------------------------------
#
if [[ ${opt_show_help} == true ]]; then
  show_help
  exit 0
fi
