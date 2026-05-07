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
    "config_file": "keycloak-issuer-config.json",
    "failures_file": "keycloak-issuer-failures.json",
    "filters_file": "keycloak-issuer-filters.json",
    "skips_file": "keycloak-issuer-skips.json"
  },
  "verifier": {
    "plan_name": "oid4vp-1final-verifier-haip-test-plan",
    "variants": "[credential_format=sd_jwt_vc][response_mode=direct_post.jwt]",
    "config_file": "keycloak-verifier-config.json",
    "failures_file": "keycloak-verifier-failures.json",
    "filters_file": "keycloak-verifier-filters.json",
    "skips_file": "keycloak-verifier-skips.json"
  }
}'

KC_REALM="oid4vci"

KC_ADMIN_USERNAME="admin"
KC_ADMIN_PASSWORD="admin"

KC_CLIENT="oid4vci-client"
KC_CLIENT2="oid4vci-client2"

# Default target if not set
: "${TARGET:=proxy}"
: "${CONFORMANCE_SERVER:=}"

echo "OpenID Conformance Suite target: $TARGET"
case "$TARGET" in
  ngrok)
    if [[ -z "${NGROK_URL:-}" ]]; then
      NGROK_URL=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null \
        | jq -r '.tunnels[] | select(.proto=="https") | .public_url' \
        | head -n 1)
    fi
    if [[ -z "${NGROK_URL:-}" || "${NGROK_URL}" == "null" ]]; then
      echo "NGROK_URL is required, or start ngrok so http://127.0.0.1:4040/api/tunnels exposes an https tunnel" >&2
      exit 1
    fi
    CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443}"
    export CONFORMANCE_DEV_MODE="${CONFORMANCE_DEV_MODE:-true}"
    export KEYCLOAK_HOSTNAME="${NGROK_URL}"
    ;;
  proxy)
    CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443}"
    export KEYCLOAK_HOSTNAME="https://keycloak.nessustech.io:8443"
    ;;
  *)
    echo "Unsupported target: $TARGET"
    exit 1
    ;;
esac

# [TODO >>>] Exporting CONFORMANCE_SERVER breaks conformance suite on docker compose
#export CONFORMANCE_SERVER
#: "${CONFORMANCE_SERVER_MTLS:=https://localhost.emobix.co.uk:8444}"
#export CONFORMANCE_SERVER_MTLS

## Parse args
#
init_opts() {
  opt_clean=false
  opt_help=false
  opt_show_client=""
  opt_show_client_scope=""
  opt_show_role=""
  opt_run_role=""
  opt_run_module=""
  opt_run_profile=""
}

init_opts

show_help() {
  echo "usage: $0 [--clean] [--help] [--show-modules role] [--run role] [--run-module role module] [--run-profile name]"
  echo ""
  echo "  --clean           Cleans existing test plans from the database"
  echo "  --run-all         Run all profiles for a given role"
  echo "  --run-module      Run a single test module"
  echo "  --run-profile     Run the given test profile"
  echo "  --show-client     Show the configuration for a given client"
  echo "  --show-scope      Show the configuration for a given client scope"
  echo "  --show-modules    Show effective test modules for a given role"
  echo ""
  echo "  Roles"
  echo "    - issuer        Issuer modules"
  echo "    - verifier      Verifier modules"
  echo ""
  echo "  Profiles"
  echo "    - [1|issuer]                                Run the default issuer profile"
  echo "    - [2|verifier]                              Run the default verifier profile"
  echo "    - [3|fapi2-user-rejects-authentication]     User rejects consent during authentication"
  echo "    - [4|oid4vci-mdoc-issuance]                 Run the mdoc issuer profile"
  echo ""
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      opt_clean=true
      ;;
    --help)
      opt_help=true
      break
      ;;
    --show-client)
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Client name required (e.g. --show-client oid4vci)" >&2
        exit 1
      fi
      opt_show_client="$2"
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
    --show-scope)
      if [[ -z "${2-}" || "${2-}" == --* ]]; then
        echo "Scope name required (e.g. --show-scope oid4vc_natural_person_sd)" >&2
        exit 1
      fi
      opt_show_client_scope="$2"
      break
      ;;
    --run-all)
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
        opt_run_module="$2"
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
  curl -ksfS "${CONFORMANCE_SERVER}/api/plan/info/${plan}" | jq -r '.modules[].testModule'
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


## Commands ------------------------------------------------------------------------------------------------------------

before_all() {
  kc_admin_login "${KC_ADMIN_USERNAME}" "${KC_ADMIN_PASSWORD}"

  kc_set_realm_attribute "${KC_REALM}" "authorization.preferErrorOnRedirect" "true"

  kc_set_client_policy_enabled "${KC_REALM}" "oid4vc-haip-policy" "false"

  openid_origin="${CONFORMANCE_SERVER%/}"
  redirect_uri="${openid_origin}/test/a/keycloak/callback"

  for client_id in "${KC_CLIENT}" "${KC_CLIENT2}"; do
    kc_set_client_property "${KC_REALM}" "${client_id}" "consentRequired" "false"
    kc_set_client_property "${KC_REALM}" "${client_id}" "webOrigins" "[\"${openid_origin}\"]"
    kc_set_client_attribute "${KC_REALM}" "${client_id}" "request.object.required" "not required"
    kc_set_client_attribute "${KC_REALM}" "${client_id}" "tls.client.certificate.bound.access.tokens" "false"
  done

  kc_set_client_property "${KC_REALM}" "${KC_CLIENT}" "redirectUris" "[\"${redirect_uri}\"]"

  # [TODO] oid4vci-1_0-issuer-happy-flow-multiple-clients fails without the trailing '*'
  kc_set_client_property "${KC_REALM}" "${KC_CLIENT2}" "redirectUris" "[\"${redirect_uri}*\"]"

  kc_set_client_policy_enabled "${KC_REALM}" "oid4vc-haip-policy" "true"
  kc_get_client ${KC_REALM} ${KC_CLIENT}
}

after_all() {
  echo "Done!"
}

# Remove existing test plans
#
clean_plans() {
  plan_ids=$(curl -ksfS "${CONFORMANCE_SERVER}/api/plan" | jq -r '.data[]._id')
  for id in $plan_ids; do
    echo "Deleting: ${id}"
    curl -ksfS -X DELETE "${CONFORMANCE_SERVER}/api/plan/${id}"
  done
}

# Run test modules
#
# - role is required, all else is optional
# - modules, variants, config are generated from defaults when not provided by the caller
run_modules() {
  local role="$1"
  local modules="${2:-}"
  local variants="${3:-}"
  local config="${4:-}"

  plan=$(_get_plan_name "${role}")
  failures="${SCRIPT_DIR}/config/$(jq -r ".${role}.failures_file" <<< "${SCRIPT_CONFIG}")"
  skips="${SCRIPT_DIR}/config/$(jq -r ".${role}.skips_file" <<< "${SCRIPT_CONFIG}")"

  if [[ -z "${variants}" ]]; then
    variants=$(jq -r ".${role}.variants" <<< "${SCRIPT_CONFIG}")
  fi

  if [[ -z "${modules}" ]]; then
    modules=$(printf "%s\n" "$(_get_effective_modules "${role}")" | paste -sd "," -)

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

  if [[ -z "${config}" ]]; then
    config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
    config_out="${SCRIPT_DIR}/config/.keycloak-${role}-config.json"
    issuer_url="${KEYCLOAK_HOSTNAME}/realms/${KC_REALM}"
    jq --arg issuer_url "${issuer_url}" '.vci.credential_issuer_url = $issuer_url' "${config_in}" > "${config_out}"
  else
    config_out="${config}"
  fi

  if [ -n "${modules}" ]; then
    _run_test_modules "${role}" "${plan}" "${variants}" "${modules}" "${failures}" "${skips}" "${config_out}"
  fi
}

# Run the default issuer profile
#
run_profile_oid4vci_default() {
  role="issuer"
  echo "Run profile: ${role}";

  run_modules "${role}"
}

run_profile_oid4vci_mdoc_issuance() {
  role="issuer"
  echo "Run profile: ${role}";

  variants="[credential_format=mdoc][vci_authorization_code_flow_variant=wallet_initiated]"
  modules="oid4vci-1_0-issuer-metadata-test,oid4vci-1_0-issuer-metadata-test-signed,oid4vci-1_0-issuer-happy-flow"

  config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  config_out="${SCRIPT_DIR}/config/.keycloak-${role}-mdoc-config.json"

  issuer_url="${KEYCLOAK_HOSTNAME}/realms/${KC_REALM}"
  credential_configuration_id="${MDOC_CREDENTIAL_CONFIGURATION_ID:-org.iso.18013.5.1.mDL}"
  jq --arg issuer_url "${issuer_url}" --arg credential_configuration_id "${credential_configuration_id}" \
    '.vci.credential_issuer_url = $issuer_url | .vci.credential_configuration_id = $credential_configuration_id' \
    "${config_in}" > "${config_out}"

  run_modules "${role}" "${modules}" "${variants}" "${config_out}"

  # [TODO >>>] Explain why we'd want to do this. How does it affect after_all?
  #  set +e
  #  run_modules "${role}" "${modules}" "${variants}" "${config_out}"
  #  status=$?
  #  set -e
  #  return "${status}"
}

# Run the default verifier profile
#
run_profile_oid4vcp_default() {
  role="verifier"
  echo "Run profile: ${role}";
  run_modules "${role}"
}

# Run a profile 'fapi2-user-rejects-authentication'
#
run_profile_fapi2_user_rejects_authentication() {
  echo "Run profile: fapi2-user-rejects-authentication"

  haip_enabled=$(kc_get_client_policy "${KC_REALM}" "oid4vc-haip-policy" | jq -r .enabled)

  kc_set_client_policy_enabled "${KC_REALM}" "oid4vc-haip-policy" "false"

  for client_id in "${KC_CLIENT}" "${KC_CLIENT2}"; do
    kc_set_client_property "${KC_REALM}" "${client_id}" "consentRequired" "true"
  done

  role="issuer"
  modules="fapi2-security-profile-final-user-rejects-authentication"
  config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  config_out="${SCRIPT_DIR}/config/.keycloak-${role}-config-fapi2-user-rejects-authentication.json"

  jq '.browser[0].tasks |=
    (.[:1] + [{
      "task": "Keycloak Consent",
      "match": "https://*/realms/oid4vci/login-actions/required-action*",
      "commands": [
        ["click", "id", "kc-cancel"]
      ]
    }] + .[1:])' "${config_in}" > "${config_out}"

  run_modules "${role}" "${modules}" "" "${config_out}"

  for client_id in "${KC_CLIENT}" "${KC_CLIENT2}"; do
    kc_set_client_property "${KC_REALM}" "${client_id}" "consentRequired" "false"
  done

  kc_set_client_policy_enabled "${KC_REALM}" "oid4vc-haip-policy" "${haip_enabled}"
}

# Show client configuration
#
show_client() {
  local name="$1"
  kc_get_client ${KC_REALM} "${name}"
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

# Show client scope configuration
#
show_client_scope() {
  local name="$1"
  kc_get_client_scope ${KC_REALM} "${name}"
}

main() {
  before_all

  # Optionally clean existing test plans -------------------------------------------------------------------------------
  #
  if [[ ${opt_clean} == true ]]; then
    clean_plans
  fi

  # Show client configuration ------------------------------------------------------------------------------------------
  #
  if [[ -n ${opt_show_client} ]]; then
    show_client "${opt_show_client}"
    return
  fi

  # Show client scope configuration ------------------------------------------------------------------------------------
  #
  if [[ -n ${opt_show_client_scope} ]]; then
    show_client_scope "${opt_show_client_scope}"
    return
  fi

  # Show help for this script ------------------------------------------------------------------------------------------
  #
  if [[ ${opt_help} == true ]]; then
    show_help
    return
  fi

  # Show pre-configured modules for the given role ---------------------------------------------------------------------
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
    return
  fi

  # Run all pre-configured modules for the given test plan -------------------------------------------------------------
  #
  if [[ -n "${opt_run_role}" && -z ${opt_run_module} ]]; then
    _activate_venv
    case "${opt_run_role}" in
      issuer)
        run_profile_fapi2_user_rejects_authentication
        run_profile_oid4vci_default
        ;;
      issuer_mdoc)
        run_profile_oid4vci_mdoc_issuance
        ;;
      verifier)
        run_profile_oid4vcp_default
        ;;
    esac
    _deactivate_venv
    return
  fi

  # Run a single module from the given test plan -----------------------------------------------------------------------
  #
  if [[ -n ${opt_run_role} && -n ${opt_run_module} ]]; then
    _activate_venv

    run_modules "${opt_run_role}" "${opt_run_module}"

    _deactivate_venv
    return
  fi

  # Run a given test profile -------------------------------------------------------------------------------------------
  #
  if [[ -n ${opt_run_profile} ]]; then
    _activate_venv
    case "${opt_run_profile}" in
      1|issuer)
        run_profile_oid4vci_default
        ;;
      2|verifier)
        run_profile_oid4vcp_default
        ;;
      3|fapi2-user-rejects-authentication)
        run_profile_fapi2_user_rejects_authentication
        ;;
      4|oid4vci-mdoc-issuance)
        run_profile_oid4vci_mdoc_issuance
        ;;
      *)
        echo "Unknown profile: $opt_run_profile";
        show_help
        exit 1
        ;;
    esac
    _deactivate_venv
    return
  fi

  after_all
}

# Show help for this script --------------------------------------------------------------------------------------------
#
if [[ ${opt_help} == true ]]; then
  show_help
  exit 0
fi

# Call main entry ------------------------------------------------------------------------------------------------------
#
main
