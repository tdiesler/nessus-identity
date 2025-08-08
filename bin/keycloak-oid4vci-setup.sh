#!/usr/bin/env bash

NID_HOME=$(realpath "$(dirname "$0")/..")
cd "${NID_HOME}"

# -e (exit on error)
# -u (unset variables are errors)
# -o pipefail (fail pipelines if any command fails)
set -euo pipefail

SERVER_URL="https://auth.localtest.me"

ADMIN_USER=$(kubectl get secret keycloak-admin -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
ADMIN_PASS=$(kubectl get secret keycloak-admin -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)

REALM="ebsi"
REALM_RECREATE=true

# Log in as admin
#
kcadm config credentials --server "${SERVER_URL}" --realm master \
    --user "${ADMIN_USER}" --password "${ADMIN_PASS}"

# Check if realm already exists
#
realm_exists=$(kcadm get realms | jq -e ".[] | select(.realm==\"${REALM}\")" >/dev/null 2>&1 && echo true || echo false)
if [[ $realm_exists == "true" ]]; then
  if [[ $REALM_RECREATE ]]; then
    kcadm delete realms/${REALM}
    echo "Deleting realm '${REALM}'"
  else
    echo "Realm '${REALM}' already exists"
    exit 0
  fi
fi

# Create realm
#
kcadm create realms -s realm="${REALM}" -s enabled=true

# 3) Create test user
kcadm create users -r "$REALM" -s username=ebsi-user -s enabled=true
kcadm set-password -r "$REALM" --username ebsi-user --new-password password --temporary=false

# Create EBSI signing keys
#
mkdir -p .secret
for user in issuer holder verifier; do
  SIGNING_KEY="secp256r1-${user}-key.jwk"
  if [ ! -f ".secret/${SIGNING_KEY}" ]; then
    echo "Creating ${user} key: ${SIGNING_KEY}"
    jose jwk gen -i '{"alg":"ES256","crv":"P-256","use":"sig"}' -o ".secret/${SIGNING_KEY}"
  else
    echo "Using ${user} key: ${SIGNING_KEY}"
  fi
done

# Configure oid4vci signing keys
#
echo "Configure oid4vci signing keys"

ISSUER_SIGNING_KEY="secp256r1-issuer-key.jwk"
jwk_json=$(jq -c . ".secret/${ISSUER_SIGNING_KEY}" | jq -Rs .)
kcadm update realms/$REALM -f - <<EOF
{
  "attributes": {
    "oid4vci.signing_keys": $jwk_json
  }
}
EOF

# Configure oid4vci realm attributes
#
echo "Configure oid4vci realm attributes"

kcadm update realms/$REALM -r master -f - <<EOF
{
  "attributes": {
    "oid4vci.vc_formats": "jwt_vc",
    "oid4vci.issuer_metadata_endpoint": "${SERVER_URL}/realms/$REALM/.well-known/openid-credential-issuer"
  }
}
EOF

# Create a client for credential issuance
#
kcadm create clients -r "$REALM" -s clientId=vc-issuer -s enabled=true \
    -s redirectUris="[\"https://app.example.com/callback\"]" \
    -s serviceAccountsEnabled=true \
    -s publicClient=false \
    -s authorizationServicesEnabled=true

# Associate client with appropriate protocol
#
CID=$(kcadm get clients -r "$REALM" -q clientId=vc-issuer 2>/dev/null | jq -r -j '.[0].id')
kcadm create clients/$CID/protocol-mappers/models -r $REALM -f - <<EOF
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
