#!/usr/bin/env bash

KCADM="kcadm"

# Log in as Keycloak Admin
#
kc_admin_login() {
  local realm="master"
  local adminUser="$1"
  local adminPass="$2"

  ${KCADM} config credentials --server "${AUTH_SERVER_URL}" \
      --realm "${realm}" \
      --user "${adminUser}" \
      --password "${adminPass}"
}

# Log in as Keycloak Admin
#
kc_oid4vci_login() {
  local realm="$1"
  local oid4vciUser="$2"
  local oid4vciPass="$3"

  ${KCADM} config credentials --server "${AUTH_SERVER_URL}" \
    --realm "${realm}" \
    --client "${oid4vciUser}" \
    --secret "${oid4vciPass}"
}

kc_create_realm() {
  local realm="$1"
  local force="$2"

  # Check if realm already exists
  #
  realm_exists=$(${KCADM} get realms | jq -e ".[] | select(.realm==\"${realm}\")" >/dev/null 2>&1 && echo true || echo false)
  if [[ $realm_exists == true ]]; then
    if [[ ${force} == true ]]; then
      ${KCADM} delete "realms/${realm}" 2>/dev/null
      echo "Deleting realm '${realm}'"
    else
      echo "Realm '${realm}' already exists"
      return 1
    fi
  fi

  # Create realm
  #

  user_profile_config=$(jq -c . <<< '{
    "attributes": [
      {
        "name": "username",
        "displayName": "${username}",
        "multivalued": false,
        "permissions": {
          "view": [ "admin", "user" ],
          "edit": [ "admin", "user" ]
        }
      },
      {
        "name": "did",
        "displayName": "DID",
        "multivalued": false,
        "permissions": {
          "view": [ "admin", "user" ],
          "edit": [ "admin", "user" ]
        }
      },
      {
        "name": "email",
        "displayName": "${email}",
        "multivalued": false,
        "permissions": {
          "view": [ "admin", "user" ],
          "edit": [ "admin", "user" ]
        }
      },
      {
        "name": "firstName",
        "displayName": "${firstName}",
        "multivalued": false,
        "permissions": {
          "view": [ "admin", "user" ],
          "edit": [ "admin", "user" ]
        }
      },
      {
        "name": "lastName",
        "displayName": "${lastName}",
        "multivalued": false,
        "permissions": {
          "view": [ "admin", "user" ],
          "edit": [ "admin", "user" ]
        }
      }
    ],
    "groups": [
      {
        "name": "user-metadata",
        "displayHeader": "User metadata",
        "displayDescription": "Attributes that describe user metadata"
      }
    ]
  }')

  escaped_profile_json=$(printf '%s' "$user_profile_config" | jq -R .)

  ${KCADM} create realms -f - <<-EOF
  {
    "realm": "oid4vci",
    "enabled": true,
    "components": {
      "org.keycloak.userprofile.UserProfileProvider": [
        {
          "name": "Declarative User Profile",
          "providerId": "declarative-user-profile",
          "config": {
            "kc.user.profile.config": [ ${escaped_profile_json} ]
          }
        }
      ]
    }
  }
EOF

  realmId=$(${KCADM} get "realms/${realm}" --fields id --format csv --noquotes)

  ## Delete Keys with unwanted algos
  #
  local curr_algos keep_algos unwanted_algos

  keep_algos=("ES256" "RS256" "RSA-OAEP")
  curr_algos=$(${KCADM} get keys -r "${realm}" 2>/dev/null | jq -r '.keys[].algorithm' | xargs | sort -u)

  unwanted_algos=()
  for alg in ${curr_algos}; do
      if [[ ! ${keep_algos[*]} =~ ${alg} ]]; then
          unwanted_algos+=("$alg")
      fi
  done

  for alg in "${unwanted_algos[@]}"; do
    local providerId
    providerId=$(${KCADM} get keys -r "${realm}" 2>/dev/null | jq -r ".keys[] | select(.algorithm==\"${alg}\") | .providerId")
    if [ -n "${providerId}" ]; then
      echo "Deleting $alg key: ${providerId}"
      ${KCADM} delete "components/${providerId}" -r "${realm}"
    fi
  done

  ## Generate a Key for signing VCs with the ES256
  #
  echo "Creating a Key with algorithm: ES256"
  ${KCADM} create components -r "${realm}" \
    -s name="es256-vc-signing" \
    -s providerId="ecdsa-generated" \
    -s providerType="org.keycloak.keys.KeyProvider" \
    -s parentId="${realmId}" \
    -s 'config.priority=["120"]' \
    -s 'config.enabled=["true"]' \
    -s 'config.active=["true"]' \
    -s 'config.algorithm=["ES256"]'

  # Get the ACTIVE ES256 kid
  es256KeyId=$(${KCADM} get keys -r "${realm}" 2>/dev/null | jq -r '.keys[] | select(.algorithm=="ES256" and .status=="ACTIVE") | .kid')
  echo "ES256 key id: ${es256KeyId}"

  curr_algos=$(${KCADM} get keys -r "${realm}" 2>/dev/null | jq -r '.keys[].algorithm' | xargs | sort -u)
  echo "Current key algorithms: ${curr_algos[*]}"

  # Fetch the realm’s public JWKS
  jwks_json=$(curl -s "${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/certs" | jq -r --arg kid "$es256KeyId" '.keys[] | select(.kid==$kid)')
  echo "Realm JWK: $jwks_json"

  # Filter JWKS by kid
  x=$(echo "$jwks_json" | jq -r '.x')
  y=$(echo "$jwks_json" | jq -r '.y')

  # Get the Issuer's DID
  #
  issuer_did=$(jbang "${SCRIPT_DIR}/es256pub_to_didkey.java" "$x" "$y")
  echo "Issuer Did: ${issuer_did}"

  # Configure oid4vci realm attributes
  #
  echo "Configure realm attributes ..."
  ${KCADM} update "realms/${realm}" -f - <<-EOF
  {
    "realm": "${realm}",
    "enabled": true,
    "verifiableCredentialsEnabled": true,
    "attributes": {
      "preAuthorizedCodeLifespanS": 120
    }
  }
EOF

  ## Show realm  attributes
  #
  ${KCADM} get "realms/${realm}" 2>/dev/null | jq -r '.attributes'

  echo
  echo "Realm setup complete"
}

kc_create_oid4vci_service_client() {
  local realm="$1"
  local client_id="$2"
  local client_secret="$3"
  local credential_id="$4"

  echo "Create service client: ${client_id} ..."
  ${KCADM} create "realms/${realm}/clients" -f - <<-EOF
  {
    "clientId": "${client_id}",
    "name": "OID4VC Service Client",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": false,
    "serviceAccountsEnabled": true,
    "directAccessGrantsEnabled": false,
    "authorizationServicesEnabled": false,
    "standardFlowEnabled": false,
    "secret": "${client_secret}",
    "attributes": {
      "oid4vci.enabled": "true"
    },
    "optionalClientScopes": ["oid4vc_natural_person", "${credential_id}"]
  }
EOF

  # Assign realm-management roles to the service account
  ${KCADM} add-roles -r "${realm}" \
    --uusername "service-account-${client_id}" \
    --cclientid realm-management \
    --rolename manage-clients 2>/dev/null
  ${KCADM} add-roles -r "${realm}" \
    --uusername "service-account-${client_id}" \
    --cclientid realm-management \
    --rolename view-clients 2>/dev/null
  ${KCADM} add-roles -r "${realm}" \
    --uusername "service-account-${client_id}" \
    --cclientid realm-management \
    --rolename manage-users 2>/dev/null
  ${KCADM} add-roles -r "${realm}" \
    --uusername "service-account-${client_id}" \
    --cclientid realm-management \
    --rolename view-users 2>/dev/null

  echo "List assigned client roles for verification ..."
  ${KCADM} get-roles -r "${realm}" --uusername "service-account-${client_id}" --cclientid realm-management
}

kc_create_oid4vc_identity_credential() {
  local realm="$1"
  local credential_id="$2"

  # Configure oid4vci client scopes
  #
  echo "Create Credential config for: ${credential_id}"
  ${KCADM} create "realms/${realm}/client-scopes" -f - <<EOF
  {
    "name": "${credential_id}",
    "protocol": "oid4vc",
    "attributes": {
      "vc.issuer_did": "${issuer_did}",
      "vc.format": "jwt_vc"
    },
    "protocolMappers": [
      {
        "name": "did",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "id",
          "userAttribute": "did",
          "vc.mandatory": "false"
        }
      },
      {
        "name": "firstName",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "firstName",
          "userAttribute": "firstName",
          "vc.mandatory": "false"
        }
      },
      {
        "name": "lastName",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "lastName",
          "userAttribute": "lastName",
          "vc.mandatory": "false"
        }
      },
      {
        "name": "email",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "email",
          "userAttribute": "email",
          "vc.mandatory": "false"
        }
      }
    ]
  }
EOF

  local client_scope_id
  client_scope_id=$(${KCADM} get "realms/${realm}/client-scopes" 2>/dev/null | jq -r ".[] | select(.name==\"${credential_id}\") | .id")
  echo "Client Scope Id for ${credential_id}: ${client_scope_id}"

  # ${KCADM} get "realms/${realm}/client-scopes/${client_scope_id}" 2>/dev/null | jq .
}

kc_create_oid4vci_client() {
  local realm="$1"
  local client_id="$2"
  local credential_id="$3"

  echo "Create OID4VCI Issuance client: ${client_id} ..."
  ${KCADM} create "realms/${realm}/clients" -f - <<-EOF
  {
    "clientId": "${client_id}",
    "name": "OID4VC Issuance Client",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": true,
    "redirectUris": ["urn:ietf:wg:oauth:2.0:oob", "${AUTH_REDIRECT_URI}"],
    "directAccessGrantsEnabled": true,
    "defaultClientScopes": ["profile"],
    "optionalClientScopes": ["oid4vc_natural_person", "${credential_id}"],
    "baseUrl": "${AUTH_SERVER_URL}/realms/${realm}/.well-known/openid-credential-issuer",
    "attributes": {
      "client.introspection.response.allow.jwt.claim.enabled": "false",
      "post.logout.redirect.uris": "${AUTH_SERVER_URL}",
      "pkce.code.challenge.method": "S256",
      "oid4vci.enabled": "true"
    }
  }
EOF

  # Inspect the Issuer's metadata
  # https://oauth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
  metadataUrl="${AUTH_SERVER_URL}/realms/${realm}/.well-known/openid-credential-issuer"
  echo "Inspect ${metadataUrl} ..."

  metadata=$(curl -s "${metadataUrl}")
  echo "${metadata}" | jq -r '.credential_configurations_supported | keys[]'
}

kc_create_user() {
  local realm="$1"
  local role="$2"
  local fullName="$3"
  local userEmail="$4"
  local userPassword="$5"

  local firstName lastName username
  firstName=$(echo "${fullName}" | awk '{print $1}')
  lastName=$(echo "${fullName}" | awk '{print $2}')
  username="$(echo "${firstName}" | tr '[:upper:]' '[:lower:]')"

  # Check if user already exists
  local userId
  userId=$(${KCADM} get users -r "${realm}" -q username="${username}" --fields id --format csv --noquotes)

  if [[ -n "${userId}" ]]; then
    echo "User '${fullName}' already exists (id=${userId})" >&2
  else
    echo "Creating user '${fullName}' with role '${role}' in realm '${realm}'" >&2
    user_did=$(jq -r '.did' ".secret/${role}-details.json")
    echo "${firstName}'s DID: ${user_did}" >&2
    ${KCADM} create users -r "${realm}" \
      -s username="${username}" \
      -s email="${userEmail}" \
      -s firstName="${firstName}" \
      -s lastName="${lastName}" \
      -s emailVerified=true \
      -s enabled=true \
      -s attributes.did="${user_did}"

    ${KCADM} set-password -r "${realm}" --username "${username}" --new-password "${userPassword}" --temporary=false

    if [[ "${role}" == "issuer" ]]; then
      ${KCADM} add-roles -r "${realm}" --uusername "${username}" --rolename "credential-offer-create"
    fi

    user_id=$(${KCADM} get users -r "${realm}" -q username="${username}" --fields id --format json | jq -r '.[0].id')
    ${KCADM} get -r "${realm}" "users/${user_id}"
  fi
}

# Verification ---------------------------------------------------------------------------------------------------------

kc_access_token_authorization_code() {
  local realm="$1"

  local tokenUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/token"

  tokenRes=$(curl -s -X POST "$tokenUrl" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${client_id}" \
    -d "code=${VC_AUTH_CODE}" \
    -d "redirect_uri=${VC_REDIRECT_URI}" \
    -d "code_verifier=${VC_CODE_VERIFIER}")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokenRes}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokenRes}" | jq -r .access_token)
  export ACCESS_TOKEN="${access_token}"
}

kc_access_token_pre_auth_code() {
  local realm="$1"

  local tokenUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/token"

  tokenRes=$(curl -s -X POST "$tokenUrl" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
    -d "client_id=${client_id}" \
    -d "pre-authorized_code=${PRE_AUTH_CODE}")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokenRes}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokenRes}" | jq -r .access_token)
  credential_identifier=$(echo "${tokenRes}" | jq -r .authorization_details[0].credential_identifiers[0])
  echo "Credential Id: ${credential_identifier}"

  export ACCESS_TOKEN="${access_token}"
  export CREDENTIAL_IDENTIFIER="${credential_identifier}"
}

kc_access_token_direct_access() {
  local realm="$1"
  local client_id="$2"
  local username="$3"
  local password="$4"

  local authUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/token"

  tokenRes=$(curl -s "${authUrl}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${client_id}" \
    -d "username=${username}" \
    -d "password=${password}" \
    -d "scope=openid")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokenRes}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokenRes}" | jq -r .access_token)
  export ACCESS_TOKEN="${access_token}"
}

kc_authorization_request() {
  local realm="$1"
  local client_id="$2"
  local credential_id="$3"

  local response_type="code"
  local redirect_uri="urn:ietf:wg:oauth:2.0:oob"

  # PKCE
  code_verifier=$(openssl rand -base64 96 | tr -d '+/=' | tr -d '\n' | cut -c -128)
  code_challenge=$(echo -n "$code_verifier" |
    openssl dgst -sha256 -binary | openssl base64 |
    tr '+/' '-_' | tr -d '=' | tr -d '\n')

  scopes="openid"
  scopes=$(printf 'openid %s' "${credential_id}" | jq -sRr @uri)

  local authUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/auth"

  # Build JSON for authorization_details
  authorization_details=$(printf '[{
    "type": "openid_credential",
    "credential_configuration_id": "%s",
    "locations": [ "%s" ]
  }]' "${credential_id}" "${AUTH_SERVER_URL}/realms/${realm}")
  echo "authorization_details=${authorization_details}"
  authorization_details_encoded=$(echo "${authorization_details}" | jq -sRr @uri)

  url="${authUrl}?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}"
  url="${url}&scope=${scopes}&authorization_details=${authorization_details_encoded}"
  url="${url}&code_challenge=${code_challenge}&code_challenge_method=S256"

  echo "Browser Url: ${url}"
  open "$url"

  read -p "Paste the authorization code here: " authCode

  # export for next step
  export VC_REDIRECT_URI="${redirect_uri}"
  export VC_AUTH_CODE="${authCode}"
  export VC_CODE_VERIFIER="${code_verifier}"
}

kc_credential_offer_uri() {
  local realm="$1"
  local client_id="$2"
  local credential_id="$3"
  local pre_authorized="$4"
  local user_id="$5"

  local credOfferUriUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/credential-offer-uri"
  credOfferUriUrl="${credOfferUriUrl}?credential_configuration_id=${credential_id}&pre_authorized=${pre_authorized}&user_id=${user_id}"

  credOfferUriRes=$(curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" "${credOfferUriUrl}")
  echo "Credential Offer Uri: ${credOfferUriRes}"

  issuer=$(echo "${credOfferUriRes}" | jq -r '.issuer')
  nonce=$(echo "${credOfferUriRes}" | jq -r '.nonce')

  # export for next step
  export CREDENTIAL_OFFER_URI="${issuer}${nonce}"
}

kc_credential_offer() {
  local realm="$1"
  local pre_authorized="$2"

  credOffer=$(curl -s "${CREDENTIAL_OFFER_URI}")
  echo "Credential Offer: ${credOffer}"

  if [[ "${pre_authorized}" == "true" ]]; then
    preAuthCode=$(echo "${credOffer}" | jq -r '.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]')
    echo "Pre-Authorized Code: ${preAuthCode}"
    export PRE_AUTH_CODE="${preAuthCode}"
  fi

  # export for next step
  export CREDENTIAL_OFFER="${credOffer}"
}

kc_credential_request() {
  local realm="$1"
  local credential_id="$2"
  local credential_configuration_id="$3"

  local nonceUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/nonce"
  c_nonce=$(curl -s -X POST "${nonceUrl}" | jq -r '.c_nonce')

  holder_details_json=".secret/holder-details.json"

  email=$(jq -r '.email' "${holder_details_json}")
  password=$(jq -r '.password' "${holder_details_json}")
  wid=$(jq -r '.wid' "${holder_details_json}")
  kid=$(jq -r '.kid' "${holder_details_json}")

  token=$(wallet_auth_login "${email}" "${password}")
  pub_jwk=$(wallet_keys_export "${token}" "${wid}" "${kid}")

  proof_header=$(jq -n -c \
    --argjson jwk "${pub_jwk}" \
    '{alg: "ES256", typ: "openid4vci-proof+jwt", jwk: $jwk}')

  proof_claims=$(jq -n -c \
    --arg aud "${AUTH_SERVER_URL}/realms/${realm}" \
    --argjson iat "$(date +%s)" \
    --arg nonce "${c_nonce}" \
    '{aud: $aud, iat:$iat, nonce: $nonce}')

  # Build the unsigned flat proof JWS
  proof_jws=$(jq -n -c \
    --arg header "$(echo -n "${proof_header}" | openssl base64 -A | tr '+/' '-_' | tr -d '=')" \
    --arg claims "$(echo -n "${proof_claims}" | openssl base64 -A | tr '+/' '-_' | tr -d '=')" \
    '{protected: $header, payload: $claims}')

  echo "ProofHeader: $(echo -n "${proof_header}" | jq .)"
  echo "ProofClaims: $(echo -n "${proof_claims}" | jq .)"
  echo "UnsignedJws: $(echo -n "${proof_jws}" | jq .)"

  proof=$(wallet_keys_sign "${token}" "${wid}" "${kid}" "${proof_jws}")

  # Credential request body
  if [[ "${credential_id}" ]]; then
    req_body=$(jq -n \
      --arg cid "${credential_id}" \
      --arg proof "${proof}" \
      '{
        credential_identifier: $cid,
        proofs: { jwt: [ $proof ] }
      }')
  else
    req_body=$(jq -n \
      --arg cid "${credential_configuration_id}" \
      --arg proof "${proof}" \
      '{
        credential_configuration_id: $cid,
        proofs: { jwt: [ $proof ] }
      }')
  fi

  echo "==== Credential Request Body ====" >&2
  echo "${req_body}" | jq . >&2
  echo "================================" >&2

  resp_json="$(curl -s -X POST "${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/credential" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "${req_body}")"
  echo "$resp_json" | jq .

  # Extract all JWTs from "credentials[].credential"
  echo "$resp_json" \
  | jq -r '.credentials[]?.credential' \
  | while IFS= read -r jwt; do
      echo
      echo "Header ..."
      printf '%s' "$jwt" \
        | jq -Rr 'split(".")[0]' \
        | jose b64 dec -i - -O- \
        | jq .

      echo "Payload ..."
      printf '%s' "$jwt" \
        | jq -Rr 'split(".")[1]' \
        | jose b64 dec -i - -O- \
        | jq .
    done
}
