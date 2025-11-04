#!/usr/bin/env bash

SCRIPT_DIR=$(realpath "$(dirname "$0")")

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

# Default target if not set
: "${TARGET:=dev}"

echo "Running setup for target: $TARGET"
case "$TARGET" in
  local)
    echo "Doing local setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export AUTH_SERVER_URL="http://localhost:8080"
    export AUTH_REDIRECT_URI="http://localhost:9000/wallet/auth/callback"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  dev)
    echo "Doing development setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export AUTH_SERVER_URL="https://oauth.localtest.me"
    export AUTH_REDIRECT_URI="http://localhost:9000/wallet/auth/callback"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  stage)
    echo "Doing staging setup..."
    export KUBE_CONTEXT="ebsi"
    export AUTH_SERVER_URL="https://oauth.nessustech.io"
    export AUTH_REDIRECT_URI="https://console.nessustech.io/wallet/auth/callback"
    export WALLET_API_URL="https://waltid-wallet-api.nessustech.io"
    ;;
  *)
    echo "Unknown target: $TARGET"
    exit 1
    ;;
esac

ISSUER=("Max Mustermann" "user@email.com" "password")
HOLDER=("Alice Wonderland" "alice@email.com" "password")
VERIFIER=("Bob Baumeister" "bob@email.com" "password")

source "${SCRIPT_DIR}/oid4vci-functions-keycloak.sh"
source "${SCRIPT_DIR}/oid4vci-functions-waltid.sh"

## Parse args
#
bare="false"
force="false"
for arg in "$@"; do
  case $arg in
    --bare)
      bare="true"
      shift
      ;;
    --force)
      force="true"
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
wallet_create_user "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[2]}" || exit 1
wallet_create_user "verifier" "${VERIFIER[0]}" "${VERIFIER[1]}" "${VERIFIER[2]}" || exit 1

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
credential_id="oid4vc_identity_credential"

kc_admin_login "${adminUser}" "${adminPass}"

if kc_create_realm "${realm}" "${force}"; then

  ## Setup Keycloak OID4VCI Service Client -------------------------------------------------------------------------------
  #
  kc_create_oid4vci_service_client "${realm}" "${oid4vciUser}" "${oid4vciPass}" "${force}"

  kc_oid4vci_login "${realm}" "${oid4vciUser}" "${oid4vciPass}"

  ## Setup OID4VCI Identity Credential -----------------------------------------------------------------------------------
  #
  kc_create_oid4vc_identity_credential "${realm}" "${credential_id}"

  ## Setup Keycloak OID4VCI Issuance Client ------------------------------------------------------------------------------
  #
  kc_create_oid4vci_client "${realm}" "${client_id}" "${credential_id}" "${force}"
fi

## Continue Setup with Alice as Holder
#
if [[ ${bare} == "false" ]]; then

  ## Setup Alice as Holder -----------------------------------------------------------------------------------------------
  #
  kc_create_user "${realm}" "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[2]}"
  wallet_create_user "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[2]}" || exit 1

  # Fetch a Credential - Authorization Flow ------------------------------------------------------------------------------
  #
  # credential_id="oid4vc_natural_person"
  kc_authorization_request "${realm}" "${client_id}" "${credential_id}"
  kc_token_request "${realm}" "${client_id}" "${credential_id}"
  kc_credential_request "${realm}" "${credential_id}"
fi

