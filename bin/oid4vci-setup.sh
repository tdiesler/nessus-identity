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
    export AUTH_SERVER_URL="https://auth.localtest.me"
    export WALLET_API_URL="https://wallet-api.localtest.me"
    ;;
  stage)
    echo "Doing staging setup..."
    export KUBE_CONTEXT="ebsi"
    export AUTH_SERVER_URL="https://auth.nessustech.io"
    export WALLET_API_URL="https://wallet-api.nessustech.io"
    ;;
  *)
    echo "Unknown target: $TARGET"
    exit 1
    ;;
esac

HOLDER_NAME="Alice Wonderland"
HOLDER_EMAIL="alice@email.com"
HOLDER_PASSWORD="password"

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
setup_waltid_holder "${HOLDER_NAME}" "${HOLDER_EMAIL}" "${HOLDER_PASSWORD}" || exit 1

## Keycloak admin login ------------------------------------------------------------------------------------------------
#
kubecmd="kubectl --context ${KUBE_CONTEXT}"
adminUser=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
adminPass=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)

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
kc_create_user "${realm}" "holder" "${HOLDER_NAME}" "${HOLDER_EMAIL}" "${HOLDER_PASSWORD}"

# Fetch a Credential - Authorization Flow ------------------------------------------------------------------------------
#
kc_authorization_request "${realm}" "${client_id}" "${credential_id}" "${redirect_uri}"

kc_token_request "${realm}" "${client_id}" "${credential_id}"

kc_credential_request "${realm}" "${credential_id}"