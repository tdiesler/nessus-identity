#!/usr/bin/env bash

SCRIPT_DIR=$(realpath "$(dirname "$0")")

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

# Default target if not set
# Keep in sync with Makefile
: "${TARGET:=local}"

echo "Running setup for target: $TARGET"
case "$TARGET" in
  local)
    echo "Doing local setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export KEYCLOAK_HOSTNAME="http://localhost:8080"
    export WALLET_REDIRECT_URI="http://localhost:9000/wallet/*"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  ngrok)
    echo "Doing local ngrok setup..."
    if [[ -z "${KEYCLOAK_HOSTNAME:-}" ]]; then
      KEYCLOAK_HOSTNAME=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null \
        | jq -r '.tunnels[] | select(.proto=="https") | .public_url' \
        | head -n 1)
    fi
    if [[ -z "${KEYCLOAK_HOSTNAME:-}" || "${KEYCLOAK_HOSTNAME}" == "null" ]]; then
      echo "KEYCLOAK_HOSTNAME is required, or start ngrok so http://127.0.0.1:4040/api/tunnels exposes an https tunnel" >&2
      exit 1
    fi
    export WALLET_REDIRECT_URI="http://localhost:9000/wallet/*"
    export WALLET_API_URL="${WALLET_API_URL:-https://waltid-wallet-api.localtest.me}"
    ;;
  proxy)
    echo "Doing development setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export KEYCLOAK_HOSTNAME="https://keycloak.nessustech.io:8443"
    export WALLET_REDIRECT_URI="http://localhost:9000/wallet/*"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  stage)
    echo "Doing staging setup..."
    export KUBE_CONTEXT="ebsi"
    export KEYCLOAK_HOSTNAME="https://keycloak.nessustech.io"
    export WALLET_REDIRECT_URI="https://console.nessustech.io/wallet/*"
    export WALLET_API_URL="https://waltid-wallet-api.nessustech.io"
    ;;
  *)
    echo "Unknown target: $TARGET"
    exit 1
    ;;
esac

ISSUER=("Max Mustermann" "user@email.com" "max" "password")
HOLDER=("Alice Wonderland" "alice@email.com" "alice" "password")
VERIFIER=("Bob Baumeister" "bob@email.com" "bob" "password")

source "${SCRIPT_DIR}/oid4vci-functions-keycloak.sh"
source "${SCRIPT_DIR}/oid4vci-functions-waltid.sh"

## Parse args
#
auth_type="preauth_code"
force="false"
skip_vc="false"
skip_wallet="false"
create_mdoc="false"

for arg in "$@"; do
  case $arg in
    --force)
      force="true"
      shift
      ;;
    --direct)
      auth_type="direct"
      shift
      ;;
    --auth-code)
      auth_type="auth_code"
      shift
      ;;
    --preauth-code)
      auth_type="preauth_code"
      shift
      ;;
    --skip-vc)
      skip_vc="true"
      shift
      ;;
    --skip-wallet)
      skip_wallet="true"
      skip_vc="true"
      shift
      ;;
    --mdoc)
      create_mdoc="true"
      shift
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

## Setup EBSI Test Users -----------------------------------------------------------------------------------------------
#
if [[ "${skip_wallet}" == "true" ]]; then
  mkdir -p ".secret"
  jq -n \
    --arg role "issuer" \
    --arg name "${ISSUER[0]}" \
    --arg email "${ISSUER[1]}" \
    --arg password "${ISSUER[3]}" \
    --arg did "did:example:issuer" \
    '{role: $role, name: $name, email: $email, password: $password, did: $did}' > ".secret/issuer-details.json"
  jq -n \
    --arg role "holder" \
    --arg name "${HOLDER[0]}" \
    --arg email "${HOLDER[1]}" \
    --arg password "${HOLDER[3]}" \
    --arg did "did:example:holder" \
    '{role: $role, name: $name, email: $email, password: $password, did: $did}' > ".secret/holder-details.json"
  jq -n \
    --arg role "verifier" \
    --arg name "${VERIFIER[0]}" \
    --arg email "${VERIFIER[1]}" \
    --arg password "${VERIFIER[3]}" \
    --arg did "did:example:verifier" \
    '{role: $role, name: $name, email: $email, password: $password, did: $did}' > ".secret/verifier-details.json"
else
  wallet_create_user "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[3]}" || exit 1
  wallet_create_user "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[3]}" || exit 1
  wallet_create_user "verifier" "${VERIFIER[0]}" "${VERIFIER[1]}" "${VERIFIER[3]}" || exit 1
fi

## Keycloak admin login ------------------------------------------------------------------------------------------------
#
if [[ "${TARGET}" == "ngrok" ]]; then
  adminUser="${KC_ADMIN_USERNAME:-admin}"
  adminPass="${KC_ADMIN_PASSWORD:-admin}"
  oid4vciUser="${KC_OID4VCI_SERVICE_ID:-oid4vci-service}"
  oid4vciPass="${KC_OID4VCI_SERVICE_SECRET:-secret}"
else
  kubecmd="kubectl --context ${KUBE_CONTEXT}"
  adminUser=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
  adminPass=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)
  oid4vciUser=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.OID4VCI_SERVICE_ID}' | base64 -d)
  oid4vciPass=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.OID4VCI_SERVICE_SECRET}' | base64 -d)
fi

## Setup Keycloak OID4VCI Realm ----------------------------------------------------------------------------------------
#
realm="oid4vci"
client_id="oid4vci-client"

kc_admin_login "${adminUser}" "${adminPass}"

if kc_create_realm "${realm}" "${force}"; then

  ## Client Policies ---------------------------------------------------------------------------------------------------
  #
  # kc_create_oid4vci_client_policies "${realm}"
  kc_create_haip_conformance_client_policies "${realm}"

  ## Service Client ----------------------------------------------------------------------------------------------------
  #
  kc_create_oid4vci_service_client "${realm}" "${oid4vciUser}" "${oid4vciPass}"

  kc_oid4vci_login "${realm}" "${oid4vciUser}" "${oid4vciPass}"

  ## Client Scopes -----------------------------------------------------------------------------------------------------
  #
  # kc_create_oid4vci_credential_configurations "${realm}"

  ## Issuance Client ---------------------------------------------------------------------------------------------------
  #
  kc_create_oid4vci_client "${realm}" "${client_id}"
  kc_create_oid4vci_client "${realm}" "${client_id}2"
  if [[ "${create_mdoc}" == "true" ]]; then
    kc_create_oid4vci_mdoc_credential_configuration "${realm}" "${MDOC_CREDENTIAL_SCOPE:-org.iso.18013.5.1.mDL}" "${MDOC_CREDENTIAL_CONFIGURATION_ID:-org.iso.18013.5.1.mDL}" "${MDOC_DOCTYPE:-org.iso.18013.5.1.mDL}"
  fi

  # Create the Attestation-Based Client Authorization Key --------------------------------------------------------------------
  #
  kc_create_abca_key "${realm}"

  ## Setup Alice as Holder -----------------------------------------------------------------------------------------------
  #
  kc_create_user "${realm}" "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[3]}"
  kc_create_user "${realm}" "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[3]}"
fi

# Fetch the Credential -------------------------------------------------------------------------------------------------
#
if [[ ${skip_vc} == "false" ]]; then
  credential_configuration_id="oid4vc_natural_person_jwt"
  credential_identifier="oid4vc_natural_person_jwt_0000"

  kc_set_client_policy_enabled "${realm}" "oid4vc-haip-policy" "false"

  kc_set_client_property "${realm}" "${client_id}" "directAccessGrantsEnabled" "true"

  if [[ ${auth_type} == "direct" ]]; then
    kc_access_token_direct "${realm}" "${client_id}" "${HOLDER[2]}" "${HOLDER[3]}" "${credential_configuration_id}"
    kc_credential_request "${realm}" "${credential_identifier}"

  elif [[ ${auth_type} == "auth_code" ]]; then
    kc_access_token_direct "${realm}" "${client_id}" "${ISSUER[2]}" "${ISSUER[3]}" "${credential_configuration_id}"
    kc_credential_offer_uri "${realm}" "${credential_configuration_id}" "${HOLDER[2]}" "false"
    kc_credential_offer "${realm}" "false"
    kc_authorization_request "${realm}" "${client_id}" "${credential_configuration_id}"
    kc_access_token_auth_code "${realm}"
    kc_credential_request "${realm}" "${credential_identifier}"

  elif [[ ${auth_type} == "preauth_code" ]]; then
    kc_access_token_direct "${realm}" "${client_id}" "${HOLDER[2]}" "${HOLDER[3]}" "${credential_configuration_id}"
    kc_credential_offer_uri "${realm}" "${credential_configuration_id}" "${HOLDER[2]}" "true"
    kc_credential_offer "${realm}" "true"
    kc_access_token_preauth_code "${realm}"
    kc_credential_request "${realm}" "${credential_identifier}"
  fi
fi
