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
KC_CLIENT_SCOPE_SD="oid4vc_natural_person_sd"
KC_OID4VP_CLIENT="${KC_OID4VP_CLIENT:-oid4vp-test-client}"
KC_OID4VP_IDP_ALIAS="${KC_OID4VP_IDP_ALIAS:-oid4vp-idp}"

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
  echo "Usage: openid-conformance [--clean] [--help] [--show-modules role] [--run role] [--run-module role module] [--run-profile name]"
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
  echo "    - [1|issuer]                                              Run the default issuer profile"
  echo "    - [2|verifier]                                            Run the default verifier profile"
  echo "    - [3|fapi2-reused-request-uri-prior-to-auth-completion]   Server enforces one-time use of request_uri"
  echo "    - [4|fapi2-user-rejects-authentication]                   User rejects consent during authentication"
  echo "    - [5|oid4vci-mdoc-issuance]                               Run the mdoc issuer profile"
  echo "    - [6|oid4vp-verifier-happy-flow]                          Run the OID4VP verifier happy-flow profile"
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
        echo "Scope name required (e.g. --show-scope ${KC_CLIENT_SCOPE_SD})" >&2
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

_url_encode() {
  jq -nr --arg value "$1" '$value | @uri'
}

# OID4VP verifier happy-flow needs per-variant Keycloak IdP updates from the
# conformance module's exposed authorization_endpoint before broker login.
_conformance_api() {
  local method="$1"
  local url="$2"
  shift 2

  local curl_args=(-ksfS -X "${method}" -H "Content-Type: application/json")
  if [[ -z "${CONFORMANCE_DEV_MODE:-}" && -n "${CONFORMANCE_TOKEN:-}" ]]; then
    curl_args+=(-H "Authorization: Bearer ${CONFORMANCE_TOKEN}")
  fi

  curl "${curl_args[@]}" "$@" "${url}"
}

_wait_for_oid4vp_module_state() {
  local module_id="$1"
  local states="$2"
  local timeout_seconds="${3:-240}"
  local deadline=$((SECONDS + timeout_seconds))
  local last_status=""
  local info
  local status

  while (( SECONDS < deadline )); do
    info=$(_conformance_api GET "${CONFORMANCE_SERVER}/api/info/${module_id}")
    status=$(jq -r '.status // ""' <<< "${info}")
    if [[ "${status}" != "${last_status}" ]]; then
      echo "module ${module_id} status: ${status}" >&2
      last_status="${status}"
    fi
    if [[ ",${states}," == *",${status},"* ]]; then
      printf "%s\n" "${info}"
      return 0
    fi
    if [[ "${status}" == "INTERRUPTED" ]]; then
      printf "%s\n" "${info}"
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for ${module_id} to reach one of: ${states}" >&2
  return 1
}

_wait_for_oid4vp_exposed_value() {
  local module_id="$1"
  local name="$2"
  local timeout_seconds="${3:-240}"
  local deadline=$((SECONDS + timeout_seconds))
  local value

  while (( SECONDS < deadline )); do
    value=$(_conformance_api GET "${CONFORMANCE_SERVER}/api/runner/${module_id}" | jq -r --arg name "${name}" '.exposed[$name] // ""')
    if [[ -n "${value}" ]]; then
      printf "%s\n" "${value}"
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for exposed value ${name} from ${module_id}" >&2
  return 1
}

_oid4vp_variant_name() {
  jq -r 'to_entries | sort_by(.key) | map("\(.key)=\(.value)") | join(",")' <<< "$1"
}

_oid4vp_authorization_request_transport() {
  local request_method="$1"
  case "${request_method}" in
    url_query)
      echo "query_parameters"
      ;;
    request_uri_signed)
      echo "request_uri"
      ;;
    *)
      echo "Unsupported OID4VP request method: ${request_method}" >&2
      return 1
      ;;
  esac
}

_oid4vp_is_excluded_variant() {
  local variant="$1"
  local request_method
  local client_id_prefix

  request_method=$(jq -r '.request_method' <<< "${variant}")
  client_id_prefix=$(jq -r '.client_id_prefix' <<< "${variant}")

  if [[ "${request_method}" == "request_uri_signed" && "${client_id_prefix}" == "redirect_uri" ]]; then
    return 0
  fi

  if [[ "${request_method}" == "url_query" && "${client_id_prefix}" =~ ^x509_(san_dns|hash)$ ]]; then
    return 0
  fi

  return 1
}

_oid4vp_update_identity_provider() {
  local variant="$1"
  local authorization_endpoint="$2"
  local request_method
  local client_id_prefix
  local authorization_request_transport
  local idp_json

  request_method=$(jq -r '.request_method' <<< "${variant}")
  client_id_prefix=$(jq -r '.client_id_prefix' <<< "${variant}")
  authorization_request_transport=$(_oid4vp_authorization_request_transport "${request_method}")

  idp_json=$(kcadm get "identity-provider/instances/${KC_OID4VP_IDP_ALIAS}" -r "${KC_REALM}")
  jq \
    --arg wallet_scheme "${authorization_endpoint}" \
    --arg authorization_request_transport "${authorization_request_transport}" \
    --arg client_id_prefix "${client_id_prefix}" \
    '.config.walletScheme = $wallet_scheme
      | .config.authorizationRequestTransport = $authorization_request_transport
      | .config.clientIdentifierPrefix = $client_id_prefix
      | del(.config.x509SanDnsName)' <<< "${idp_json}" \
    | kcadm update "identity-provider/instances/${KC_OID4VP_IDP_ALIAS}" -r "${KC_REALM}" -f -
}

_oid4vp_drive_keycloak_login() {
  local redirect_uri="${CONFORMANCE_SERVER%/}/test/a/keycloak/callback"
  local auth_url

  auth_url="${KEYCLOAK_HOSTNAME%/}/realms/${KC_REALM}/protocol/openid-connect/auth"
  auth_url="${auth_url}?client_id=$(_url_encode "${KC_OID4VP_CLIENT}")"
  auth_url="${auth_url}&redirect_uri=$(_url_encode "${redirect_uri}")"
  auth_url="${auth_url}&response_type=code"
  auth_url="${auth_url}&scope=openid%20profile"
  auth_url="${auth_url}&kc_idp_hint=$(_url_encode "${KC_OID4VP_IDP_ALIAS}")"

  echo "Starting Keycloak broker login: ${auth_url}"
  curl -ksfSL --cookie-jar /tmp/oid4vp-keycloak-login-cookies.txt --cookie /tmp/oid4vp-keycloak-login-cookies.txt "${auth_url}" > /dev/null
}

_run_oid4vp_happy_flow_variant() {
  local plan_name="oid4vp-1final-verifier-test-plan"
  local module_name="oid4vp-1final-verifier-happy-flow"
  local variant="$1"
  local signing_jwk="${CONFORMANCE_SCRIPTS_DIR}/certs-keys/vp-signing-jwk.json"
  local config_out="${SCRIPT_DIR}/config/.keycloak-oid4vp-happy-flow-config.json"
  local dns_name
  local plan_id
  local module_id
  local info
  local authorization_endpoint
  local final_status
  local final_result

  dns_name=$(sed -E 's#^[^:]+://##; s#/.*$##; s#:.*$##' <<< "${KEYCLOAK_HOSTNAME}")
  echo "Running variant: $(_oid4vp_variant_name "${variant}")"

  if [[ "$(jq -r '.client_id_prefix' <<< "${variant}")" == "x509_san_dns" ]]; then
    jq -n \
      --slurpfile signing_jwk "${signing_jwk}" \
      --arg dns_name "${dns_name}" \
      '{
        alias: "keycloak-oid4vp-happy-flow",
        description: "Keycloak OID4VP verifier happy-flow",
        credential: {
          signing_jwk: $signing_jwk[0]
        },
        client: {
          client_id: $dns_name
        }
      }' > "${config_out}"
  else
    jq -n \
      --slurpfile signing_jwk "${signing_jwk}" \
      '{
        alias: "keycloak-oid4vp-happy-flow",
        description: "Keycloak OID4VP verifier happy-flow",
        credential: {
          signing_jwk: $signing_jwk[0]
        }
      }' > "${config_out}"
  fi

  plan_id=$(_conformance_api POST \
    "${CONFORMANCE_SERVER}/api/plan?planName=${plan_name}&variant=$(_url_encode "${variant}")" \
    --data "@${config_out}" | jq -r '.id')
  echo "Created test plan: ${CONFORMANCE_SERVER%/}/plan-detail.html?plan=${plan_id}"

  module_id=$(_conformance_api POST \
    "${CONFORMANCE_SERVER}/api/runner?test=${module_name}&plan=${plan_id}" | jq -r '.id')
  echo "Created test module: ${CONFORMANCE_SERVER%/}/log-detail.html?log=${module_id}"

  info=$(_wait_for_oid4vp_module_state "${module_id}" "CONFIGURED,WAITING,FINISHED")
  if [[ "$(jq -r '.status // ""' <<< "${info}")" == "CONFIGURED" ]]; then
    _conformance_api POST "${CONFORMANCE_SERVER}/api/runner/${module_id}" > /dev/null
    _wait_for_oid4vp_module_state "${module_id}" "WAITING,FINISHED" > /dev/null
  fi

  authorization_endpoint=$(_wait_for_oid4vp_exposed_value "${module_id}" "authorization_endpoint")
  echo "Authorization endpoint: ${authorization_endpoint}"
  _oid4vp_update_identity_provider "${variant}" "${authorization_endpoint}"
  _oid4vp_drive_keycloak_login

  info=$(_wait_for_oid4vp_module_state "${module_id}" "FINISHED,INTERRUPTED")
  final_status=$(jq -r '.status // ""' <<< "${info}")
  final_result=$(jq -r '.result // ""' <<< "${info}")
  echo "Final result: status=${final_status} result=${final_result}"

  _conformance_api GET "${CONFORMANCE_SERVER}/api/log/${module_id}" \
    | jq -r 'limit(20; .[] | select(.result == "FAILURE" or .result == "WARNING") | "\(.result): \(.condition // .conditionId // .src // "") \(.msg // .message // .error // "")")'

  [[ "${final_status}" == "FINISHED" && ( "${final_result}" == "PASSED" || "${final_result}" == "WARNING" ) ]]
}


## Commands ------------------------------------------------------------------------------------------------------------

before_all() {
  kc_admin_login "${KC_ADMIN_USERNAME}" "${KC_ADMIN_PASSWORD}"

  kc_set_client_policy_enabled "${KC_REALM}" "oid4vc-haip-policy" "false"

  openid_origin="${CONFORMANCE_SERVER%/}"
  redirect_uri="${openid_origin}/test/a/keycloak/callback"

  for client_id in "${KC_CLIENT}" "${KC_CLIENT2}"; do
    kc_set_client_attribute "${KC_REALM}" "${client_id}" "dpop.bound.access.tokens" "true"
    kc_set_client_attribute "${KC_REALM}" "${client_id}" "request.object.required" "not required"
    kc_set_client_attribute "${KC_REALM}" "${client_id}" "tls.client.certificate.bound.access.tokens" "false"
    kc_set_client_property "${KC_REALM}" "${client_id}" "consentRequired" "false"
    kc_set_client_property "${KC_REALM}" "${client_id}" "webOrigins" "[\"${openid_origin}\"]"
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
    trust_anchor="$(cat "$(mkcert -CAROOT)/rootCA.pem")"
    jq --arg issuer_url "${issuer_url}" --arg trust_anchor "${trust_anchor}" \
      '.vci.credential_issuer_url = $issuer_url | .credential.trust_anchor_pem = $trust_anchor | .credential.status_list_trust_anchor_pem = $trust_anchor' \
      "${config_in}" > "${config_out}"
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
}

# Run the default verifier profile
#
run_profile_oid4vcp_default() {
  role="verifier"
  echo "Run profile: ${role}";
  run_modules "${role}"
}

run_profile_oid4vp_verifier_happy_flow() {
  echo "Run profile: oid4vp-verifier-happy-flow"

  kc_create_oid4vp_verifier_signing_key "${KC_REALM}"
  kc_create_oid4vp_client "${KC_REALM}" "${KC_OID4VP_CLIENT}"
  kc_create_oid4vp_identity_provider "${KC_REALM}" "${KC_OID4VP_IDP_ALIAS}" "openid4vp://"

  local variant
  local request_method
  local client_id_prefix

  for request_method in url_query request_uri_signed; do
    for client_id_prefix in redirect_uri x509_san_dns x509_hash; do
      variant=$(jq -cn \
        --arg request_method "${request_method}" \
        --arg client_id_prefix "${client_id_prefix}" \
        '{
          vp_profile: "plain_vp",
          credential_format: "sd_jwt_vc",
          response_mode: "direct_post",
          request_method: $request_method,
          client_id_prefix: $client_id_prefix
        }')

      if _oid4vp_is_excluded_variant "${variant}"; then
        echo "Skipping excluded variant: $(_oid4vp_variant_name "${variant}")"
        continue
      fi

      _run_oid4vp_happy_flow_variant "${variant}"
    done
  done
}

# Run a profile 'fapi2-reused-request-uri-prior-to-auth-completion'
#
run_profile_fapi2_reused_request_uri_prior_to_auth_completion() {
  echo "Run profile: fapi2-reused-request-uri-prior-to-auth-completion"

  role="issuer"
  modules="fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds"
  config_in="${SCRIPT_DIR}/config/$(jq -r ".${role}.config_file" <<< "${SCRIPT_CONFIG}")"
  config_out="${SCRIPT_DIR}/config/.keycloak-${role}-config-fapi2-reused-request-uri-prior-to-auth-completion.json"

  # This config has no automated browser interaction.
  # While this runs, go the WebUI and complete the module there
  jq 'del(.browser)' "${config_in}" > "${config_out}"

  set +e
  run_modules "${role}" "${modules}" "" "${config_out}"
  set -e
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

  # Show help for this script ------------------------------------------------------------------------------------------
  #
  if [[ ${opt_help} == true ]]; then
    show_help
    return
  fi

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

    before_all
    _activate_venv

    case "${opt_run_role}" in
      issuer)
        run_profile_fapi2_reused_request_uri_prior_to_auth_completion
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
    after_all
    return
  fi

  # Run a single module from the given test plan -----------------------------------------------------------------------
  #
  if [[ -n ${opt_run_role} && -n ${opt_run_module} ]]; then

    before_all
    _activate_venv

    run_modules "${opt_run_role}" "${opt_run_module}"

    _deactivate_venv
    after_all
    return
  fi

  # Run a given test profile -------------------------------------------------------------------------------------------
  #
  if [[ -n ${opt_run_profile} ]]; then

    before_all
    _activate_venv

    case "${opt_run_profile}" in
      1|issuer)
        run_profile_oid4vci_default
        ;;
      2|verifier)
        run_profile_oid4vp_verifier_happy_flow
        # run_profile_oid4vcp_default
        ;;
      3|fapi2-reused-request-uri-prior-to-auth-completion)
        run_profile_fapi2_reused_request_uri_prior_to_auth_completion
        ;;
      4|fapi2-user-rejects-authentication)
        run_profile_fapi2_user_rejects_authentication
        ;;
      5|oid4vci-mdoc-issuance)
        run_profile_oid4vci_mdoc_issuance
        ;;
      6|oid4vp-verifier-happy-flow)
        run_profile_oid4vp_verifier_happy_flow
        ;;
      *)
        echo "Unknown profile: $opt_run_profile";
        show_help
        exit 1
        ;;
    esac

    _deactivate_venv
    after_all
    return
  fi
}

# Call main entry ------------------------------------------------------------------------------------------------------
#
main
