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

REALM="oid4vci"
REALM_RECREATE="false"

ISSUER_NAME="Max Mustermann"
ISSUER_EMAIL="user@email.com"
ISSUER_PASSWORD="password"

HOLDER_NAME="Alice Wonderland"
HOLDER_EMAIL="alice@email.com"
HOLDER_PASSWORD="alice"

VERIFIER_NAME="Bob Baumeister"
VERIFIER_EMAIL="bob@email.com"
VERIFIER_PASSWORD="bob"

source "${SCRIPT_DIR}/oid4vci-functions-keycloak.sh"
source "${SCRIPT_DIR}/oid4vci-functions-waltid.sh"

## Setup WaltId Users
#
setup_waltid_issuer "${ISSUER_NAME}" "${ISSUER_EMAIL}" "${ISSUER_PASSWORD}" || exit 1
setup_waltid_holder "${HOLDER_NAME}" "${HOLDER_EMAIL}" "${HOLDER_PASSWORD}" || exit 1
setup_waltid_verifier "${VERIFIER_NAME}" "${VERIFIER_EMAIL}" "${VERIFIER_PASSWORD}" || exit 1

## Setup the Keycloak OID4VCI Realm
#
kc_admin_login
kc_oid4vci_realm_create "${REALM}" ${REALM_RECREATE}

## Setup Alice as Holder
#
kc_user_create "${REALM}" "${HOLDER_NAME}" "${HOLDER_EMAIL}" "${HOLDER_PASSWORD}"

kc_authorization_request "$REALM"
echo "VC_CLIENT_ID=${VC_CLIENT_ID}"
echo "VC_CLIENT_SECRET=${VC_CLIENT_SECRET}"
echo "VC_REDIRECT_URI=${VC_REDIRECT_URI}"
echo "VC_CODE_VERIFIER=${VC_CODE_VERIFIER}"
echo "VC_AUTH_CODE=${VC_AUTH_CODE}"

kc_token_request "$REALM"
echo "VC_ACCESS_TOKEN=${VC_ACCESS_TOKEN}"

# Fetch the credential
kc_get_credential "$REALM"