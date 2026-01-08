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
    export ISSUER_BASE_URL="http://localhost:8080"
    export WALLET_REDIRECT_URI="http://localhost:9000/wallet/*"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  dev)
    echo "Doing development setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export ISSUER_BASE_URL="https://oauth.localtest.me"
    export WALLET_REDIRECT_URI="http://localhost:9000/wallet/*"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  stage)
    echo "Doing staging setup..."
    export KUBE_CONTEXT="ebsi"
    export ISSUER_BASE_URL="https://oauth.nessustech.io"
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
force="false"
skip_verify="false"
verify_oauth="false"
for arg in "$@"; do
  case $arg in
    --force)
      force="true"
      shift
      ;;
    --verify-oauth)
      verify_oauth="true"
      shift
      ;;
    --skip-verify)
      skip_verify="true"
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
wallet_create_user "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[3]}" || exit 1
wallet_create_user "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[3]}" || exit 1
wallet_create_user "verifier" "${VERIFIER[0]}" "${VERIFIER[1]}" "${VERIFIER[3]}" || exit 1

## Keycloak admin login ------------------------------------------------------------------------------------------------
#
kubecmd="kubectl --context ${KUBE_CONTEXT}"
adminUser=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
adminPass=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)
oid4vciUser=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.OID4VCI_SERVICE_ID}' | base64 -d)
oid4vciPass=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.OID4VCI_SERVICE_SECRET}' | base64 -d)

## Setup Keycloak OID4VCI Realm ----------------------------------------------------------------------------------------
#
realm="oid4vci"
client_id="oid4vci-client"

kc_admin_login "${adminUser}" "${adminPass}"

if kc_create_realm "${realm}" "${force}"; then

  ## Setup Keycloak OID4VCI Service Client -------------------------------------------------------------------------------
  #
  kc_create_oid4vci_service_client "${realm}" "${oid4vciUser}" "${oid4vciPass}"

  kc_oid4vci_login "${realm}" "${oid4vciUser}" "${oid4vciPass}"

  ## Setup OID4VCI Identity Credential -----------------------------------------------------------------------------------
  #
  kc_create_oid4vc_credential_configurations "${realm}"

  ## Setup Keycloak OID4VCI Issuance Client ------------------------------------------------------------------------------
  #
  kc_create_oid4vci_client "${realm}" "${client_id}"
fi

## Setup Alice as Holder -----------------------------------------------------------------------------------------------
#
kc_create_user "${realm}" "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[3]}"
kc_create_user "${realm}" "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[3]}"

# Fetch the Credential from a Pre-Authorized Offer -----------------------------------------------------------------------
#
if [[ ${skip_verify} == "false" ]]; then
  credential_id="oid4vc_natural_person_jwt"

  kc_access_token_direct_access "${realm}" "${client_id}" "${ISSUER[2]}" "${ISSUER[3]}"
  kc_credential_offer_uri "${realm}" "${client_id}" "${credential_id}" "true" "${HOLDER[2]}"
  kc_credential_offer "${realm}" "true"
  kc_access_token_pre_auth_code "${realm}"
  kc_credential_request "${realm}" "${CREDENTIAL_IDENTIFIER}" ""
fi

# Fetch the Credential from an unauthorized Offer ----------------------------------------------------------------------
#
if [[ ${verify_oauth} == "true" ]]; then
  credential_id="oid4vc_natural_person_sd"

  kc_access_token_direct_access "${realm}" "${client_id}" "${ISSUER[2]}" "${ISSUER[3]}"
  kc_credential_offer_uri "${realm}" "${client_id}" "${credential_id}" "false" "${HOLDER[2]}"
  kc_credential_offer "${realm}" "false"
  kc_authorization_request "${realm}" "${client_id}" "${credential_id}"
  kc_access_token_authorization_code "${realm}" "${client_id}" "${credential_id}"
  kc_credential_request "${realm}" "" "${credential_id}"
fi
