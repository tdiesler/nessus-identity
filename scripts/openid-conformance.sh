#!/usr/bin/env bash

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

SCRIPT_DIR=$(realpath "$(dirname "$0")")

CONFORMANCE_DIR=$(realpath "${SCRIPT_DIR}/../../conformance-suite")
CONFORMANCE_SCRIPTS_DIR="${CONFORMANCE_DIR}/scripts"

SCRIPT_CONFIG='{
  "issuer": {
    "plan_name": "oid4vci-1_0-issuer-haip-test-plan",
    "variants": "[credential_format=sd_jwt_vc][vci_authorization_code_flow_variant=wallet_initiated]",
    "config_file": "keycloak-openid-issuer-config.json",
    "failures_file": "keycloak-openid-issuer-failures.json",
    "filters_file": "keycloak-openid-issuer-filters.json",
    "skips_file": "keycloak-openid-issuer-skips.json"
  },
  "verifier": {
    "plan_name": "oid4vp-1final-verifier-haip-test-plan",
    "variants": "[credential_format=sd_jwt_vc][response_mode=direct_post.jwt]",
    "config_file": "keycloak-openid-verifier-config.json",
    "failures_file": "keycloak-openid-verifier-failures.json",
    "filters_file": "keycloak-openid-verifier-filters.json",
    "skips_file": "keycloak-openid-verifier-skips.json"
  }
}'

KC_REALM="oid4vci"

KC_ADMIN_USERNAME="admin"
KC_ADMIN_PASSWORD="admin"

KC_CLIENT="oid4vci-client"
KC_CLIENT2="oid4vci-client2"

# Default target if not set
: "${TARGET:=proxy}"

echo "OpenID Conformance Suite target: $TARGET"
case "$TARGET" in
  proxy)
    CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443"
    export ISSUER_BASE_URL="https://keycloak.nessustech.io:8443"
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
  opt_show_role=""
  opt_run_role=""
  opt_run_config=""
  opt_run_module=""
  opt_run_profile=""
}

init_opts

show_help() {
  echo "usage: $0 [--clean] [--help] [--show-modules role] [--run role] [--run-module role module] [--run-profile name]"
  echo ""
  echo "  --clean           Cleans existing test plans from the database"
  echo "  --run             Run all profiles for a given role"
  echo "  --run-module      Run a single test module"
  echo "  --run-profile     Run the given test profile"
  echo "  --show-modules    Show effective test modules for a given role"
  echo ""
  echo "  Roles"
  echo "    - issuer        Issuer modules"
  echo "    - verifier      Verifier modules"
  echo ""
  echo "  Profiles"
  echo "    - [1|issuer]                              Run the default issuer profile"
  echo "    - [2|verifier]                            Run the default verifier profile"
  echo "    - [3|oid4vci-attestation-proof]           Uses proof type 'attestation' instead of 'jwt'"
  echo "    - [4|oid4vci-credential-encryption]       Variant [vci_credential_encryption=encrypted]"
  echo "    - [5|fapi2-user-rejects-authentication]   Use rejects consent during authentication"
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
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Role name required (e.g. --show-modules issuer)" >&2
        exit 1
      fi
      opt_show_role="$2"
      shift
      ;;
    --run)
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Role name required (e.g. --run issuer)" >&2
        exit 1
      fi
      opt_run_role="$2"
      shift
      ;;
    --run-module)
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Role name required (e.g. --run-module issuer)" >&2
        exit 1
      fi
      opt_run_role="$2"
      shift
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        case "${opt_run_role}" in
          issuer)
            opt_run_module="oid4vci-1_0-issuer-happy-flow"
            ;;
          verifier)
            opt_run_module="oid4vp-1final-verifier-happy-flow"
            ;;
        esac
      else
        opt_run_module="$3"
        shift
      fi
      if [[ -n "${2-}" && "${2-}" != --* ]]; then
        opt_run_config="$2"
        shift
      fi
      ;;
    --run-profile)
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Profile name/index is required (e.g. --run-profile default)" >&2
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

## Internal Functions --------------------------------------------------------------------------------------------------

_activate_venv() {
  pushd "${CONFORMANCE_SCRIPTS_DIR}" > /dev/null
  source .venv/bin/activate
}

_deactivate_venv() {
  deactivate
  popd > /dev/null
}

_get_effective_modules() {
  local role="$1"
  plan=$(_get_plan_name "${role}")
  filtered_modules=$(_get_filtered_modules "${role}")
  while IFS= read -r mod; do
    if ! printf "%s\n" "${filtered_modules}" | grep -F -x -q "$mod"; then
      printf "%s\n" "$mod"
    fi
  done <<< "$(_get_modules "${plan}")"
}

_get_filtered_modules() {
  local role="$1"
  filters_file=$(jq -r ".${role}.filters_file" <<< "${SCRIPT_CONFIG}")
  jq -r '.[]."test-name"' "${SCRIPT_DIR}/config/${filters_file}"
}

_get_modules() {
  local plan="$1"
  curl -ks "${CONFORMANCE_SERVER}/api/plan/info/${plan}" | jq -r '.modules[].testModule'
}

_get_plan_name() {
  local role="$1"
  jq -r ".${role}.plan_name" <<< "${SCRIPT_CONFIG}"
}

_run_test_modules() {
  local role="$1"
  local plan="$2"
  local variants="$3"
  local modules="$4"
  local failures="$5"
  local skips="$6"
  local config="$7"

  local cmd_args=(--no-parallel --verbose)

  if [[ -n "${failures}" ]]; then
    cmd_args+=(--expected-failures-file "${failures}")
  fi

  if [[ -n "${skips}" ]]; then
    cmd_args+=(--expected-skips-file "${skips}")
  fi

  echo "./run-test-plan.py ${cmd_args[*]} ${plan}${variants}:${modules} ${config}"
  ./run-test-plan.py "${cmd_args[@]}" "${plan}${variants}:${modules}" "${config}"
}


## CLI Commands --------------------------------------------------------------------------------------------------------

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
  local role="$1"
  local modules="$2"
  local config="$3"

  plan=$(_get_plan_name "${role}")
  variants=$(jq -r ".${role}.variants" <<< "${SCRIPT_CONFIG}")
  failures="${SCRIPT_DIR}/config/$(jq -r ".${role}.failures_file" <<< "${SCRIPT_CONFIG}")"
  skips="${SCRIPT_DIR}/config/$(jq -r ".${role}.skips_file" <<< "${SCRIPT_CONFIG}")"

  if [[ -z "${modules}" ]]; then
    modules=$(printf "%s\n" "$(_get_effective_modules ${role})" | paste -sd "," -)

    filtered_modules=$(_get_filtered_modules "${role}")
    if [ -n "$filtered_modules" ]; then
      echo "Filtered modules for test plan ${plan}"
      for mod in $filtered_modules; do
        printf " - %s\n" "$mod"
      done
    fi
  else
    failures=""
    skips=""
  fi

  if [ -n "${modules}" ]; then
    _run_test_modules "${role}" "${plan}" "${variants}" "${modules}" "${failures}" "${skips}" "${config}"
  fi
}

# Run the default profile for the given role
#
run_profile() {
  local role="$1"
  echo "Run profile: ${role}";
  config="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  run_modules "${role}" "" "${config}"
}

# Run the profile verifier
#
run_profile_verifier() {
  role="verifier"
  echo "Run profile: ${role}";
  config="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  run_modules "${role}" "" "${config}"
}

# Run a profile 'oid4vci-attestation-proof'
#
run_profile_oid4vci_attestation_proof() {
  echo "Run profile: oid4vci-attestation-proof";

  role="issuer"
  plan=$(_get_plan_name "${role}")
  variants=$(jq -r ".${role}.variants" <<< "${SCRIPT_CONFIG}")
  modules="oid4vci-1_0-issuer-fail-invalid-key-attestation-signature"
  config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  config_out="${SCRIPT_DIR}/config/.keycloak-openid-config-oid4vci-attestation-proof.json"

  # Transform the config
  jq '.vci.credential_proof_type_hint = "attestation"' "${config_in}" > "${config_out}"

  _run_test_modules "${role}" "${plan}" "${variants}" "${modules}" "" "" "${config_out}"
}

# Run a profile 'oid4vci-credential-encryption'
#
run_profile_oid4vci_credential_encryption() {
  echo "Run profile: oid4vci-credential-encryption";

  role="issuer"
  plan=$(_get_plan_name "${role}")
  variants=$(jq -r ".${role}.variants" <<< "${SCRIPT_CONFIG}")
  modules="oid4vci-1_0-issuer-happy-flow,oid4vci-1_0-issuer-fail-unknown-credential-configuration"
  config="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"

  _run_test_modules "${role}" "${plan}" "${variants}" "${modules}" "" "" "${config}"
}

# Run a profile 'fapi2-user-rejects-authentication'
#
run_profile_fapi2_user_rejects_authentication() {
  echo "Run profile: fapi2-user-rejects-authentication"

  kc_admin_login "${KC_ADMIN_USERNAME}" "${KC_ADMIN_PASSWORD}"

  cid1=$(kc_get_client ${KC_REALM} ${KC_CLIENT} | jq -r '.id')
  kcadm update "clients/${cid1}" -r ${KC_REALM} -s consentRequired=true
  echo "${KC_CLIENT} ${cid1} consentRequired=true"

  cid2=$(kc_get_client ${KC_REALM} ${KC_CLIENT2} | jq -r '.id')
  kcadm update "clients/${cid2}" -r ${KC_REALM} -s consentRequired=true
  echo "${KC_CLIENT2} ${cid2} consentRequired=true"

  role="issuer"
  plan=$(_get_plan_name "${role}")
  variants=$(jq -r ".${role}.variants" <<< "${SCRIPT_CONFIG}")
  modules="fapi2-security-profile-final-user-rejects-authentication"
  config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  config_out="${SCRIPT_DIR}/config/.keycloak-openid-config-fapi2-user-rejects-authentication.json"

  jq '.browser[0].tasks |=
    (.[:1] + [{
      "task": "Keycloak Consent",
      "match": "https://*/realms/oid4vci/login-actions/required-action*",
      "commands": [
        ["click", "id", "kc-cancel"]
      ]
    }] + .[1:])' "${config_in}" > "${config_out}"

  _run_test_modules "${role}" "${plan}" "${variants}" "${modules}" "" "" "${config_out}"

  kcadm update "clients/${cid1}" -r ${KC_REALM} -s consentRequired=false
  kcadm update "clients/${cid2}" -r ${KC_REALM} -s consentRequired=false
}

# Show effective test modules
#
show_modules() {
  local role="$1"
  
  plan=$(_get_plan_name "${role}")
  effective_modules=$(_get_effective_modules "${role}")
  filtered_modules=$(_get_filtered_modules "${role}")

  echo "Modules for test plan ${plan}"
  for mod in ${effective_modules}; do
    printf " - %s\n" "$mod"
  done

  if [ -n "$filtered_modules" ]; then
    echo "Filtered modules for test plan ${plan}"
    for mod in $filtered_modules; do
      printf " - %s\n" "$mod"
    done
  fi
}


# Optionally clean existing test plans ---------------------------------------------------------------------------------
#
if [[ ${opt_clean} == true ]]; then
  clean_plans
fi

# Show pre-configured modules for the given role -----------------------------------------------------------------------
#
if [[ -n ${opt_show_role} ]]; then
  _activate_venv
  case "${opt_show_role}" in
    issuer)
      show_modules "${opt_show_role}"
      ;;
    verifier)
      show_modules "${opt_show_role}"
      ;;
  esac
  _deactivate_venv
  exit 0
fi

# Run all pre-configured modules for the given test plan ---------------------------------------------------------------
#
if [[ -n "${opt_run_role}" && -z ${opt_run_module} ]]; then
  _activate_venv
  case "${opt_run_role}" in
    issuer)
      run_profile_fapi2_user_rejects_authentication
      run_profile_oid4vci_attestation_proof
      run_profile_issuer
      ;;
    verifier)
      run_profile "${opt_run_role}"
      ;;
  esac
  _deactivate_venv
  exit 0
fi

# Run a single module from the given test plan -------------------------------------------------------------------------
#
if [[ -n ${opt_run_role} && -n ${opt_run_module} ]]; then
  _activate_venv
  default_config="${SCRIPT_DIR}/config/$(jq -r ".${opt_run_role}.config_file" <<< "${SCRIPT_CONFIG}")"
  run_modules "${opt_run_role}" "${opt_run_module}" "${opt_run_config:-$default_config}"
  _deactivate_venv
  exit 0
fi

# Run a given test profile ---------------------------------------------------------------------------------------------
#
if [[ -n ${opt_run_profile} ]]; then
  _activate_venv
  case "${opt_run_profile}" in
    1|issuer)
      run_profile "issuer"
      ;;
    2|verifier)
      run_profile "verifier"
      ;;
    3|oid4vci-attestation-proof)
      run_profile_oid4vci_attestation_proof
      ;;
    4|oid4vci-credential-encryption)
      run_profile_oid4vci_credential_encryption
      ;;
    5|fapi2-user-rejects-authentication)
      run_profile_fapi2_user_rejects_authentication
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
