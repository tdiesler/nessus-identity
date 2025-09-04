#!/usr/bin/env bash

SCRIPT_DIR=$(realpath "$(dirname "$0")")

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

# Default target if not set
: "${TARGET:=dev}"

# shellcheck disable=SC1090
source "${SCRIPT_DIR}/oid4vci-functions.sh"

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
REALM_RECREATE=true

ISSUER_NAME="Max"
ISSUER_EMAIL="user@email.com"
ISSUER_PASSWORD="password"

HOLDER_NAME="Alice"
HOLDER_EMAIL="alice@email.com"
HOLDER_PASSWORD="password"

VERIFIER_NAME="Bob"
VERIFIER_EMAIL="bob@email.com"
VERIFIER_PASSWORD="password"

## Setup WaltId Users --------------------------------------------------------------------------------------------------

setup_waltid_issuer "${ISSUER_NAME}" "${ISSUER_EMAIL}" "${ISSUER_PASSWORD}" || exit 1
setup_waltid_holder "${HOLDER_NAME}" "${HOLDER_EMAIL}" "${HOLDER_PASSWORD}" || exit 1
setup_waltid_verifier "${VERIFIER_NAME}" "${VERIFIER_EMAIL}" "${VERIFIER_PASSWORD}" || exit 1

## Keycloak --------------------------------------------------------------------------------------------------------------

kubecmd="kubectl --context ${KUBE_CONTEXT}"
KC_ADMIN_USER=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
KC_ADMIN_PASS=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)

# Log in as admin
#
kcadm config credentials --server "${AUTH_SERVER_URL}" --realm master \
    --user "${KC_ADMIN_USER}" --password "${KC_ADMIN_PASS}"

# Check if realm already exists
#
realm_exists=$(kcadm get realms | jq -e ".[] | select(.realm==\"${REALM}\")" >/dev/null 2>&1 && echo true || echo false)
if [[ $realm_exists == true ]]; then
  if [[ $REALM_RECREATE == true ]]; then
    kcadm delete realms/${REALM}
    echo "Deleting realm '${REALM}'"
  else
    echo "Realm '${REALM}' already exists"
  fi
fi

# Create realm
#
kcadm create realms -s realm="${REALM}" -s enabled=true

# Create Issuer User
#
lowerName="$(echo "$ISSUER_NAME" | tr '[:upper:]' '[:lower:]')"
kcadm create users -r "$REALM" -s username="${lowerName}" -s enabled=true
kcadm set-password -r "$REALM" --username "${lowerName}" --new-password "${ISSUER_PASSWORD}" --temporary=false

# Configure oid4vci signing key
#
echo "Configure OID4VCI signing key"

jwk_json=$(jq -c . ".secret/secp256r1-issuer-key.jwk" | jq -Rs .)
kcadm update realms/$REALM -f - <<EOF
{
  "attributes": {
    "oid4vci.signing_keys": $jwk_json
  }
}
EOF

# Configure oid4vci realm attributes
#
echo "Configure OID4VCI realm attributes"

kcadm update realms/$REALM -r master -f - <<EOF
{
  "attributes": {
    "oid4vci.vc_formats": "jwt_vc",
    "oid4vci.issuer_metadata_endpoint": "${AUTH_SERVER_URL}/realms/$REALM/.well-known/openid-credential-issuer"
  }
}
EOF

# Create a client for credential issuance
#
kcadm create clients -r "$REALM" -s clientId=vc-issuer -s enabled=true \
    -s redirectUris="[\"https://app.example.com/callback\"]" \
    -s authorizationServicesEnabled=true \
    -s serviceAccountsEnabled=true \
    -s publicClient=false

# Associate client with appropriate protocol
#
clientId=$(kcadm get clients -r "$REALM" -q clientId=vc-issuer 2>/dev/null | jq -r -j '.[0].id')
kcadm create "clients/${clientId}/protocol-mappers/models" -r $REALM -f - <<EOF
{
  "name": "user_info",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "consentRequired": false,
  "config": {
    "user.attribute": "email",
    "claim.name": "email",
    "jsonType.label": "String"
  }
}
EOF

echo "OID4VCI setup complete"
