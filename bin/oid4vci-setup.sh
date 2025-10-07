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
  dev)
    echo "Doing development setup..."
    export KUBE_CONTEXT="rancher-desktop"
    export AUTH_SERVER_URL="https://oauth.localtest.me"
    export WALLET_API_URL="https://waltid-wallet-api.localtest.me"
    ;;
  stage)
    echo "Doing staging setup..."
    export KUBE_CONTEXT="ebsi"
    export AUTH_SERVER_URL="https://oauth.nessustech.io"
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
forceRecreate="false"
for arg in "$@"; do
  case $arg in
    --force)
      forceRecreate="true"
      shift
      ;;
    *)
      echo "Unknown option: $arg"
      exit 1
      ;;
  esac
done

## Setup WaltId Users --------------------------------------------------------------------------------------------------
#
setup_waltid_user "issuer" "${ISSUER[0]}" "${ISSUER[1]}" "${ISSUER[2]}" || exit 1
setup_waltid_user "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[2]}" || exit 1
setup_waltid_user "verifier" "${VERIFIER[0]}" "${VERIFIER[1]}" "${VERIFIER[2]}" || exit 1

## Keycloak admin login ------------------------------------------------------------------------------------------------
#
kubecmd="kubectl --context ${KUBE_CONTEXT}"
adminUser=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
adminPass=$(${kubecmd} get secret keycloak-secret -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)

kc_admin_login "${adminUser}" "${adminPass}"

## Setup the Keycloak OID4VCI Realm ------------------------------------------------------------------------------------
#
realm="oid4vci"
client_id="oid4vci-client"
credential_format="jwt_vc"
credential_id="oid4vc_identity_credential"
redirect_uri="urn:ietf:wg:oauth:2.0:oob"

kc_create_realm "${realm}" "${client_id}" "${credential_id}" "${credential_format}" ${forceRecreate}

## Setup Alice as Holder -----------------------------------------------------------------------------------------------
#
kc_create_user "${realm}" "holder" "${HOLDER[0]}" "${HOLDER[1]}" "${HOLDER[2]}"

# Fetch a Credential - Authorization Flow ------------------------------------------------------------------------------
#
credential_id="oid4vc_natural_person"
kc_authorization_request "${realm}" "${client_id}" "${credential_id}" "${redirect_uri}"

kc_token_request "${realm}" "${client_id}" "${credential_id}"

kc_credential_request "${realm}" "${credential_id}"