#!/usr/bin/env bash

# Log in as Keycloak Admin
#
kc_admin_login() {
  local realm="master"
  local adminUser="$1"
  local adminPass="$2"

  kcadm config credentials --server "${ISSUER_BASE_URL}" \
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

  kcadm config credentials --server "${ISSUER_BASE_URL}" \
    --realm "${realm}" \
    --client "${oid4vciUser}" \
    --secret "${oid4vciPass}"
}

kc_create_abca_key() {
  local realm="$1"

  abca_jwk_key_priv=".secret/keycloak_abca_jwk_priv.json"
  abca_jwk_key_pub=".secret/keycloak_abca_jwk.json"

  if [[ ! -f "${abca_jwk_key_priv}" ]]; then
    echo "Generate ABCA private key"
    jbang "${SCRIPT_DIR}/keycloak_abca_sig_rsa.java" | jq . > "${abca_jwk_key_priv}"
  fi

  jq '[ .keys[0] | del(.d, .p, .q, .dp, .dq, .qi) ]' "${abca_jwk_key_priv}" > "${abca_jwk_key_pub}"

  abca_config_value=$(jq -c . "${abca_jwk_key_priv}")
  escaped_config_value=$(printf '%s' "${abca_config_value}" | jq -Rs .)

  authenticator_id=$(kcadm get authentication/flows/clients/executions -r "${realm}" 2>/dev/null | jq -r '.[] | select(.providerId=="attestation-based") | .id')

  echo "Creating ABCA config"
  kcadm create authentication/executions/"${authenticator_id}"/config -r "${realm}" \
    -s alias="attestation-based" \
    -s "config.attester_jwks=${escaped_config_value}"
}

kc_create_realm() {
  local realm="$1"
  local force="$2"

  # Check if realm already exists
  #
  realm_exists=$(kcadm get realms | jq -e ".[] | select(.realm==\"${realm}\")" >/dev/null 2>&1 && echo true || echo false)
  if [[ $realm_exists == true ]]; then
    if [[ ${force} == true ]]; then
      kcadm delete "realms/${realm}" 2>/dev/null
      echo "Deleting realm '${realm}'"
    else
      echo "Realm '${realm}' already exists"
      return 1
    fi
  fi

  # Create realm
  #

  kcadm create realms -f - <<-EOF
  {
    "realm": "oid4vci",
    "enabled": true,
    "verifiableCredentialsEnabled": true,
    "attributes": {
      "authorization.preferErrorOnRedirect": true,
      "oid4vci.request.zip.algorithms": "DEF",
      "preAuthorizedCodeLifespanS": 120
    },
    "components": {
      "org.keycloak.userprofile.UserProfileProvider": [
        {
          "name": "Declarative User Profile",
          "providerId": "declarative-user-profile"
        }
      ]
    }
  }
EOF

  ## Show realm attributes
  #
  kcadm get "realms/${realm}" 2>/dev/null | jq -r '.attributes'

  realmId=$(kcadm get "realms/${realm}" --fields id --format csv --noquotes)

  ## Delete Keys with unwanted algos
  #
  local curr_algos keep_algos unwanted_algos

  keep_algos=("ES256" "RS256" "RSA-OAEP" "ECDH-ES")
  curr_algos=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r '.keys[].algorithm' | xargs | sort -u)

  unwanted_algos=()
  for alg in ${curr_algos}; do
      if [[ ! ${keep_algos[*]} =~ ${alg} ]]; then
          unwanted_algos+=("$alg")
      fi
  done

  for alg in "${unwanted_algos[@]}"; do
    local providerId
    providerId=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r ".keys[] | select(.algorithm==\"${alg}\") | .providerId")
    if [ -n "${providerId}" ]; then
      echo "Deleting $alg key: ${providerId}"
      kcadm delete "components/${providerId}" -r "${realm}"
    fi
  done

  ## Generate a signing key for signing VCs with the ES256
  #
  echo "Creating a Key with algorithm: ES256"
  es256KeyProv=$(kcadm create components -r "${realm}" \
    -s name="es256-vc-signing" \
    -s providerId="ecdsa-generated" \
    -s providerType="org.keycloak.keys.KeyProvider" \
    -s parentId="${realmId}" \
    -s 'config.keyUse=["sig"]' \
    -s 'config.priority=["120"]' \
    -s 'config.enabled=["true"]' \
    -s 'config.active=["true"]' \
    -s 'config.algorithm=["ES256"]' -o)

  echo "ES256 Key: ${es256KeyProv}"

  # Generate an EC encryption key provider for ECDH-ES
  #
  echo "Creating a Key with algorithm: ECDH-ES"
  ecdhKeyProv=$(kcadm create components -r "${realm}" \
    -s name="ecdh-vc-encryption" \
    -s providerId="ecdh-generated" \
    -s providerType="org.keycloak.keys.KeyProvider" \
    -s parentId="${realmId}" \
    -s 'config.keyUse=["enc"]' \
    -s 'config.priority=["130"]' \
    -s 'config.enabled=["true"]' \
    -s 'config.active=["true"]' \
    -s 'config.ecdhAlgorithm=["ECDH-ES"]' -o)

  echo "ECDH-ES Key: ${ecdhKeyProv}"

  curr_algos=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r '.keys[].algorithm' | xargs | sort -u)
  echo "Current key algorithms: ${curr_algos[*]}"

  # Fetch the realm’s public JWKS
  es256KeyProvId=$(echo "${es256KeyProv}" | jq -r .id)
  es256Kid=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r --arg pid "${es256KeyProvId}" '.keys[] | select(.providerId==$pid) | .kid')

  jwks_json=$(curl -s "${ISSUER_BASE_URL}/realms/${realm}/protocol/openid-connect/certs" | jq -r --arg kid "${es256Kid}" '.keys[] | select(.kid==$kid)')
  echo "Realm JWK: $jwks_json"

  # Filter JWKS by kid
  x=$(echo "$jwks_json" | jq -r '.x')
  y=$(echo "$jwks_json" | jq -r '.y')

  # Get the Issuer's DID
  #
  issuer_did=$(jbang "${SCRIPT_DIR}/es256pub_to_didkey.java" "$x" "$y")
  echo "Issuer Did: ${issuer_did}"

  echo
  echo "Realm setup complete"
}

kc_create_oid4vci_client_policies() {
  local realm="$1"

  # Configure client profiles
  #
  echo "Configure realm client policy profiles ..."
  kcadm update "client-policies/profiles" -r "${realm}" -f - <<-EOF
  {
    "profiles": [
      {
        "name": "oid4vci-client-profile",
        "executors": [
          {
            "executor": "oid4vci-policy-executor",
            "configuration": {}
          }
        ]
      }
    ]
  }
EOF

  ## Show client profiles
  #
  kcadm get client-policies/profiles -r "${realm}"

  # Configure client policies
  #
  echo "Configure realm client policies ..."
  kcadm update "client-policies/policies" -r "${realm}" -f - <<-EOF
  {
    "policies": [
      {
        "name": "oid4vci-offer-required",
        "description": "Client policy to determine whether a credential offers is required",
        "enabled": false,
        "conditions": [
          {
            "condition": "client-attributes",
            "configuration": {
              "attributes": "[{\"key\":\"oid4vci.enabled\", \"value\":\"true\"}]"
            }
          }
        ],
        "profiles": [
          "oid4vci-client-profile"
        ]
      },
      {
        "name": "oid4vci-offer-preauth-allowed",
        "description": "Client policy to determine whether 'pre-authorized_code' grant credential offers can be issued",
        "enabled": true,
        "conditions": [
          {
            "condition": "client-attributes",
            "configuration": {
              "attributes": "[{\"key\":\"oid4vci.enabled\", \"value\":\"true\"}]"
            }
          }
        ],
        "profiles": [
          "oid4vci-client-profile"
        ]
      }
    ]
  }
EOF

  ## Show client policies
  #
  kcadm get client-policies/policies -r "${realm}"
}

kc_create_haip_conformance_client_policies() {
  local realm="$1"

  # Configure client profiles
  #
  echo "Configure realm client policy profiles ..."
  kcadm update "client-policies/profiles" -r "${realm}" -f - <<-EOF
  {
    "profiles": [
      {
        "name": "oid4vc-haip-profile",
        "description": "Client profile, which enforces clients to conform to the OpenID4VC High Assurance Interoperability Profile 1.0",
        "executors": [
          {
            "executor": "dpop-bind-enforcer",
            "configuration": {
              "auto-configure": "true",
              "enforce-authorization-code-binding-to-dpop": "false",
              "allow-only-refresh-token-binding": "false"
            }
          },
          {
            "executor": "full-scope-disabled",
            "configuration": {
              "auto-configure": true
            }
          },
          {
            "executor": "holder-of-key-enforcer",
            "configuration": {
              "auto-configure": "true"
            }
          },
          {
            "executor": "pkce-enforcer",
            "configuration": {
              "auto-configure": "true"
            }
          },
          {
            "executor": "reject-implicit-grant",
            "configuration": {
              "auto-configure": "true"
            }
          },
          {
            "executor": "secure-client-authentication-assertion",
            "configuration": {}
          },
          {
            "executor": "secure-client-authenticator",
            "configuration": {
              "allowed-client-authenticators": [
                "client-jwt",
                "client-x509"
              ],
              "default-client-authenticator": "client-jwt"
            }
          },
          {
            "executor": "secure-client-uris",
            "configuration": {}
          },
          {
            "executor": "secure-par-content",
            "configuration": {}
          },
          {
            "executor": "secure-request-object",
            "configuration": {
              "verify-nbf": true,
              "available-period": "3600",
              "encryption-required": false
            }
          },
          {
            "executor": "secure-signature-algorithm",
            "configuration": {
              "default-algorithm": "PS256"
            }
          },
          {
            "executor": "secure-signature-algorithm-signed-jwt",
            "configuration": {
              "require-client-assertion": false
            }
          }
        ]
      }
    ]
  }
EOF

  ## Show client profiles
  #
  kcadm get client-policies/profiles -r "${realm}"

  # Configure client policies
  #
  echo "Configure realm client policies ..."
  kcadm update "client-policies/policies" -r "${realm}" -f - <<-EOF
  {
    "policies": [
      {
        "name": "oid4vc-haip-policy",
        "description": "Client policy that enables the oid4vc-haip-profile",
        "enabled": false,
        "conditions": [
          {
            "condition": "client-attributes",
            "configuration": {
              "attributes": "[{\"key\":\"oid4vci.enabled\", \"value\":\"true\"}]"
            }
          }
        ],
        "profiles": [
          "oid4vc-haip-profile"
        ]
      }
    ]
  }
EOF

  ## Show client policies
  #
  kcadm get client-policies/policies -r "${realm}"
}

kc_create_oid4vci_service_client() {
  local realm="$1"
  local client_id="$2"
  local client_secret="$3"

  echo "Create service client: ${client_id} ..."
  kcadm create "realms/${realm}/clients" -f - <<-EOF
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
    "optionalClientScopes": [
      "oid4vc_natural_person_sd",
      "oid4vc_natural_person_jwt"
    ]
  }
EOF

  # Assign roles manage-clients roles to the service account
  kcadm add-roles -r "${realm}" \
    --uusername "service-account-${client_id}" \
    --cclientid realm-management \
    --rolename manage-clients \
    --rolename manage-realm \
    --rolename manage-users 2>/dev/null

  echo "List assigned client roles for verification ..."
  kcadm get-roles -r "${realm}" --uusername "service-account-${client_id}" --cclientid realm-management
}

kc_create_oid4vci_credential_configurations() {
  local realm="$1"

  # Configure oid4vci client scopes
  #
  for credential_identifier in "CTWalletSameAuthorisedInTime" "CTWalletSameAuthorisedDeferred" "CTWalletSamePreAuthorisedInTime" "CTWalletSamePreAuthorisedDeferred"; do
    echo "Create Credential config for: ${credential_identifier}"
    kcadm create "realms/${realm}/client-scopes" -f - <<EOF
    {
      "name": "${credential_identifier}",
      "protocol": "oid4vc",
      "attributes": {
        "vc.issuer_did": "${issuer_did}",
        "vc.credential_signing_alg": "ES256",
        "vc.format": "jwt_vc_json"
      },
      "protocolMappers": [
        {
          "name": "subject-id",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-subject-id-mapper",
          "config": {
            "claim.name": "id",
            "userAttribute": "did",
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

    client_scope_id=$(kcadm get "realms/${realm}/client-scopes" 2>/dev/null | jq -r ".[] | select(.name==\"${credential_identifier}\") | .id")
    echo "Client Scope Id for ${credential_identifier}: ${client_scope_id}"
    kcadm get "realms/${realm}/client-scopes/${client_scope_id}" 2>/dev/null | jq .
  done
}

kc_create_oid4vci_client() {
  local realm="$1"
  local client_id="$2"

  openid_redirect_uri="https://localhost.emobix.co.uk:8443/test/a/keycloak/callback"
  if [[ "${client_id}" == "oid4vci-client2" ]]; then
    # [TODO] oid4vci-1_0-issuer-happy-flow-multiple-clients fails without the trailing '*'
    openid_redirect_uri="${openid_redirect_uri}*"
  fi

  echo "Create OID4VCI Issuance client: ${client_id} ..."
  kcadm create "realms/${realm}/clients" -f - <<-EOF
  {
    "clientId": "${client_id}",
    "name": "OID4VC Issuance Client",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": true,
    "directAccessGrantsEnabled": true,
    "redirectUris": ["urn:ietf:wg:oauth:2.0:oob", "${WALLET_REDIRECT_URI}", "https://oauth.pstmn.io/v1/callback", "${openid_redirect_uri}"],
    "defaultClientScopes": ["profile"],
    "optionalClientScopes": [
      "oid4vc_natural_person_sd",
      "oid4vc_natural_person_jwt"
    ],
    "baseUrl": "${ISSUER_BASE_URL}/realms/${realm}/.well-known/openid-credential-issuer",
    "attributes": {
      "client.introspection.response.allow.jwt.claim.enabled": "false",
      "post.logout.redirect.uris": "${ISSUER_BASE_URL}",
      "oid4vci.enabled": "true"
    }
  }
EOF

  # Inspect the Issuer's metadata
  # https://oauth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
  metadataUrl="${ISSUER_BASE_URL}/realms/${realm}/.well-known/openid-credential-issuer"
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
  userId=$(kcadm get users -r "${realm}" -q username="${username}" --fields id --format csv --noquotes)

  if [[ -n "${userId}" ]]; then
    echo "User '${fullName}' already exists (id=${userId})" >&2
  else
    echo "Creating user '${fullName}' with role '${role}' in realm '${realm}'" >&2
    user_did=$(jq -r '.did' ".secret/${role}-details.json")
    echo "${firstName}'s DID: ${user_did}" >&2
    kcadm create users -r "${realm}" \
      -s username="${username}" \
      -s email="${userEmail}" \
      -s firstName="${firstName}" \
      -s lastName="${lastName}" \
      -s emailVerified=true \
      -s enabled=true \
      -s attributes.did="${user_did}"

    echo "Setting password [username=${username}, password=${userPassword}]" >&2
    kcadm set-password -r "${realm}" --username "${username}" --new-password "${userPassword}" --temporary=false

    if [[ "${role}" == "issuer" ]]; then
      local roleName="credential-offer-create"
      echo "Adding role [username=${username}, role=${roleName}]" >&2
      kcadm add-roles -r "${realm}" --uusername "${username}" --rolename "${roleName}"
    fi

    user_id=$(kcadm get users -r "${realm}" -q username="${username}" --fields id --format json | jq -r '.[0].id')
    kcadm get -r "${realm}" "users/${user_id}"
  fi
}

# Verification ---------------------------------------------------------------------------------------------------------

kc_authorization_request() {
  local realm="$1"
  local client_id="$2"
  local credential_configuration_id="$3"

  local response_type="code"
  local openid_redirect_uri="urn:ietf:wg:oauth:2.0:oob"

  # PKCE
  code_verifier=$(openssl rand -base64 96 | tr -d '+/=' | tr -d '\n' | cut -c -128)
  code_challenge=$(echo -n "$code_verifier" |
    openssl dgst -sha256 -binary | openssl base64 |
    tr '+/' '-_' | tr -d '=' | tr -d '\n')

  local authUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/openid-connect/auth"

  # Build JSON for authorization_details
  authorization_details=$(printf '[{
    "type": "openid_credential",
    "credential_configuration_id": "%s",
    "locations": [ "%s" ]
  }]' "${credential_configuration_id}" "${ISSUER_BASE_URL}/realms/${realm}")
  echo "authorization_details=${authorization_details}"
  authorization_details_encoded=$(echo "${authorization_details}" | jq -sRr @uri)

  url="${authUrl}?response_type=${response_type}&client_id=${client_id}&openid_redirect_uri=${openid_redirect_uri}"
  url="${url}&scope=openid+${credential_configuration_id}&authorization_details=${authorization_details_encoded}"
  url="${url}&code_challenge=${code_challenge}&code_challenge_method=S256"

  echo "Browser Url: ${url}"
  open "$url"

  read -p "Paste the authorization code here: " authCode

  # export for next step
  export VC_REDIRECT_URI="${openid_redirect_uri}"
  export VC_AUTH_CODE="${authCode}"
  export VC_CODE_VERIFIER="${code_verifier}"
}

kc_access_token_auth_code() {
  local realm="$1"

  local tokenUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/openid-connect/token"

  tokenRes=$(curl -s -X POST "$tokenUrl" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${client_id}" \
    -d "code=${VC_AUTH_CODE}" \
    -d "openid_redirect_uri=${VC_REDIRECT_URI}" \
    -d "code_verifier=${VC_CODE_VERIFIER}")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokenRes}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokenRes}" | jq -r .access_token)
  export ACCESS_TOKEN="${access_token}"
}

kc_access_token_preauth_code() {
  local realm="$1"

  local tokenUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/openid-connect/token"

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
  credential_configuration_id=$(echo "${tokenRes}" | jq -r .authorization_details[0].credential_configuration_id)
  echo "Credential Configuration Id: ${credential_configuration_id}"

  export ACCESS_TOKEN="${access_token}"
  export CREDENTIAL_CONFIGURATION_ID="${credential_configuration_id}"
}

kc_access_token_direct() {
  local realm="$1"
  local client_id="$2"
  local username="$3"
  local password="$4"
  local credential_configuration_id="$5"

  local authUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/openid-connect/token"

  # Build JSON for authorization_details
  authorization_details=$(printf '[{
    "type": "openid_credential",
    "credential_configuration_id": "%s",
    "locations": [ "%s" ]
  }]' "${credential_configuration_id}" "${ISSUER_BASE_URL}/realms/${realm}")
  echo "authorization_details=${authorization_details}"
  authorization_details_encoded=$(echo "${authorization_details}" | jq -sRr @uri)

  tokenRes=$(curl -s "${authUrl}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${client_id}" \
    -d "username=${username}" \
    -d "password=${password}" \
    -d "scope=openid+${credential_configuration_id}" \
    -d "authorization_details=${authorization_details_encoded}")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokenRes}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokenRes}" | jq -r .access_token)
  export ACCESS_TOKEN="${access_token}"
}

kc_credential_offer_uri() {
  local realm="$1"
  local credential_configuration_id="$2"
  local target_user="$3"
  local pre_authorized="$4"

  local credOfferUriUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/oid4vc/create-credential-offer"
  credOfferUriUrl="${credOfferUriUrl}?credential_configuration_id=${credential_configuration_id}&target_user=${target_user}&pre_authorized=${pre_authorized}"

  credOfferUriRes=$(curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" "${credOfferUriUrl}")
  echo "Credential Offer Uri: ${credOfferUriRes}"

  issuer=$(echo "${credOfferUriRes}" | jq -r '.issuer')
  nonce=$(echo "${credOfferUriRes}" | jq -r '.nonce')

  # export for next step
  export CREDENTIAL_OFFER_URI="${issuer}/${nonce}"
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
  local credential_identifier="$2"

  local nonceUrl="${ISSUER_BASE_URL}/realms/${realm}/protocol/oid4vc/nonce"
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
    --arg aud "${ISSUER_BASE_URL}/realms/${realm}" \
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
  req_body=$(jq -n \
    --arg cid "${credential_identifier}" \
    --arg proof "${proof}" \
    '{
      credential_identifier: $cid,
      proofs: { jwt: [ $proof ] }
    }')

  echo "==== Credential Request Body ====" >&2
  echo "${req_body}" | jq . >&2
  echo "================================" >&2

  resp_json="$(curl -s -X POST "${ISSUER_BASE_URL}/realms/${realm}/protocol/oid4vc/credential" \
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

# Get a client config by clientId
#
kc_get_client() {
  local realm="$1"
  local clientId="$2"
  kcadm get clients -r "${realm}" -q clientId="${clientId}" 2>/dev/null | jq -r '.[0]'
}

kc_set_client_attribute() {
  local realm="$1"
  local clientId="$2"
  local attrName="$3"
  local attrValue="$4"

  echo "Set client attribute ${clientId} ${attrName} => ${attrValue}"
  cid=$(kc_get_client "${realm}" "${clientId}" | jq -r '.id')
  kcadm update -r "${realm}" "clients/${cid}" -s "attributes.\"${attrName}\"=${attrValue}"
}

kc_set_client_property() {
  local realm="$1"
  local clientId="$2"
  local propName="$3"
  local propValue="$4"

  echo "Set client property ${clientId} ${propName} => ${propValue}"
  cid=$(kc_get_client "${realm}" "${clientId}" | jq -r '.id')
  kcadm update "clients/${cid}" -r "${realm}" -s "${propName}=${propValue}"
}

# Get Client Policy
#
kc_get_client_policy() {
  local realm="$1"
  local policy="$2"
  kcadm get client-policies/policies -r "${realm}" 2>/dev/null | jq --arg policy "${policy}" '.policies[] | select(.name==$policy)'
}

# Enable/Disable Client Policy
#
kc_set_client_policy_enabled() {
  local realm="$1"
  local policy="$2"
  local enabled="$3"

  echo "Set client policy ${policy} enabled => ${enabled}"
  kcadm get client-policies/policies -r "${realm}" 2>/dev/null \
  | jq --arg policy "${policy}" --arg enabled "${enabled}" '(.policies[] | select(.name==$policy) | .enabled) = $enabled' \
  | kcadm update "client-policies/policies" -r "${realm}" -f - 2>/dev/null
}

# Get a client scope config by name
#
kc_get_client_scope() {
  local realm="$1"
  local scopeName="$2"
  sid=$(kcadm get client-scopes -r "${realm}" | jq -r --arg name "${scopeName}" '.[] | select(.name == $name) | .id')
  kcadm get "client-scopes/${sid}" -r "${realm}" 2>/dev/null | jq -r .
}

kc_set_realm_attribute() {
  local realm="$1"
  local attrName="$2"
  local attrValue="$3"

  echo "Set realm attribute ${realm} ${attrName} => ${attrValue}"
  kcadm update "realms/${realm}" -s "attributes.\"${attrName}\"=${attrValue}"
}

