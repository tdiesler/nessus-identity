#!/usr/bin/env bash

# Log in as Keycloak Admin
#
kc_admin_login() {
  local adminUser="$1"
  local adminPass="$2"

  kcadm config credentials --server "${AUTH_SERVER_URL}" --realm master \
      --user "${adminUser}" --password "${adminPass}"
}

kc_create_realm() {
  local realm="$1"
  local client_id="$2"
  local credential_id="$3"
  local credential_format="$4"
  local force="$5"


  # Check if realm already exists
  #
  realm_exists=$(kcadm get realms | jq -e ".[] | select(.realm==\"${realm}\")" >/dev/null 2>&1 && echo true || echo false)
  if [[ $realm_exists == true ]]; then
    if [[ ${force} == true ]]; then
      kcadm delete "realms/${realm}" 2>/dev/null
      echo "Deleting realm '${realm}'"
    else
      echo "Realm '${realm}' already exists"
      return 0
    fi
  fi

  # Create realm
  #
  kcadm create realms -s realm="${realm}" -s enabled=true
  realmId=$(kcadm get "realms/${realm}" --fields id --format csv --noquotes)

  ## Delete Keys with unwanted algos
  #
  local curr_algos keep_algos unwanted_algos

  keep_algos=("ES256" "RS256" "RSA-OAEP")
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

  ## Generate a Key for signing VCs with the ES256
  #
  echo "Creating a Key with algorithm: ES256"
  kcadm create components -r "${realm}" \
    -s name="es256-vc-signing" \
    -s providerId="ecdsa-generated" \
    -s providerType="org.keycloak.keys.KeyProvider" \
    -s parentId="${realmId}" \
    -s 'config.priority=["120"]' \
    -s 'config.enabled=["true"]' \
    -s 'config.active=["true"]' \
    -s 'config.algorithm=["ES256"]'

  # 2) Get the ACTIVE ES256 kid
  local es256KeyId
  es256KeyId=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r '.keys[] | select(.algorithm=="ES256" and .status=="ACTIVE" and .use=="SIG") | .kid')
  echo "ES256 key id: ${es256KeyId}"

  curr_algos=$(kcadm get keys -r "${realm}" 2>/dev/null | jq -r '.keys[].algorithm' | xargs | sort -u)
  echo "Current key algorithms: ${curr_algos[*]}"

  # Configure oid4vci realm attributes
  #
  echo "Configure realm attributes ..."
  kcadm update "realms/${realm}" -f - <<-EOF
  {
    "realm": "${realm}",
    "enabled": true,
    "attributes": {
      "preAuthorizedCodeLifespanS": 120
    }
  }
EOF

  ## Show realm  attributes
  #
  kcadm get "realms/${realm}" 2>/dev/null | jq -r '.attributes'

  ## Apply the profile to the realm
  #
  # shellcheck disable=SC2016
  did_attr='{
    "name": "did",
    "displayName": "${email}",
    "multivalued": false,
    "permissions": { "view": ["admin"], "edit": ["admin"] },
    "required": { "roles": [ "user" ] },
    "validations": {
      "pattern": {
        "pattern": "^did:.*$",
        "error-message": "invalidDid"
      }
    }
  }'
  users_profile=$(kcadm get "realms/${realm}/users/profile" 2>/dev/null)
  # echo "Current users profile ..." && echo "${users_profile}" | jq .

  users_profile=$(echo "${users_profile}" | jq \
      --argjson did_attr "${did_attr}" \
      '.attributes = ((.attributes // []) + [$did_attr] | unique_by(.name))')
  # echo "Updated users profile ..." && echo "${users_profile}" | jq .

  echo "Updating users profile ..."
  echo "$users_profile" | kcadm update "realms/${realm}/users/profile" -f -

  # Configure oid4vci client scopes
  #
  echo "Create client scopes ..."
  kcadm create "realms/${realm}/client-scopes" -f - <<EOF
  {
    "name": "${credential_id}",
    "protocol": "oid4vc",
    "attributes": {
      "include.in.token.scope": "true",
      "vc.include_in_metadata": "true",

      "vc.issuer_did": "${AUTH_SERVER_URL}/realms/${realm}",

      "vc.format": "${credential_format}",
      "vc.credential_contexts": "${credential_id}",
      "vc.credential_configuration_id": "${credential_id}",
      "vc.supported_credential_types": "${credential_id}",
      "vc.verifiable_credential_type": "${credential_id}",

      "vc.cryptographic_binding_methods_supported": "jwk",
      "vc.proof_signing_alg_values_supported": "ES256",

      "vc.expiry_in_seconds": "31536000",
      "vc.signing_key_id": "${es256KeyId}"
    },
    "protocolMappers": [
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
      },
      {
        "name": "did",
        "protocol": "oid4vc",
        "protocolMapper": "oid4vc-user-attribute-mapper",
        "config": {
          "claim.name": "id",
          "userAttribute": "did",
          "vc.mandatory": "false"
        }
      }
    ]
  }
EOF

  # Create a client for credential issuance
  #
  echo "Create OIDC client: ${client_id} ..."
  kcadm create "realms/${realm}/clients" -f - <<-EOF
  {
    "clientId": "${client_id}",
    "enabled": true,
    "protocol": "openid-connect",
    "publicClient": false,
    "serviceAccountsEnabled": true,
    "clientAuthenticatorType": "client-secret",
    "redirectUris": ["https://app.example.com/callback", "urn:ietf:wg:oauth:2.0:oob"],
    "directAccessGrantsEnabled": true,
    "defaultClientScopes": ["profile"],
    "optionalClientScopes": ["${credential_id}"],
    "attributes": {
      "client.introspection.response.allow.jwt.claim.enabled": "false",
      "post.logout.redirect.uris": "${AUTH_SERVER_URL}",
      "oid4vci.enabled": "true"
    }
  }
EOF

  # Inspect the Issuer's metadata
  # https://auth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
  local metadataUrl metadata
  metadataUrl="${AUTH_SERVER_URL}/realms/${realm}/.well-known/openid-credential-issuer"
  echo "Inspect ${metadataUrl} ..."

  metadata=$(curl -s "${metadataUrl}")
  echo "${metadata}" | jq -r '.credential_configurations_supported | keys[]'

  echo
  echo "OID4VCI setup complete"
}

kc_create_user() {
  local realm="$1"
  local role="$2"
  local userName="$3"
  local userEmail="$4"
  local userPassword="$5"

  local firstName lastName lowerName
  firstName=$(echo "${userName}" | awk '{print $1}')
  lastName=$(echo "${userName}" | awk '{print $2}')
  lowerName="$(echo "${firstName}" | tr '[:upper:]' '[:lower:]')"

  # Check if user already exists
  local userId
  userId=$(kcadm get users -r "${realm}" -q username="${lowerName}" --fields id --format csv --noquotes)

  if [[ -n "${userId}" ]]; then
    echo "User '${userName}' already exists (id=${userId})" >&2
  else
    echo "Creating user '${userName}' with role '${role}' in realm '${realm}'" >&2
    did=$(jq -r '.did' ".secret/${role}-details.json")
    kcadm create users -r "${realm}" \
      -s username="${lowerName}" \
      -s email="${userEmail}" \
      -s firstName="${firstName}" \
      -s lastName="${lastName}" \
      -s emailVerified=true \
      -s enabled=true \
      -s "attributes.did=${did}"

    kcadm set-password -r "${realm}" --username "${lowerName}" --new-password "${userPassword}" --temporary=false
  fi
}

kc_authorization_request() {
  local realm="$1"
  local client_id="$2"
  local credential_id="$3"
  local redirect_uri="$4"

  local response_type="code"

  # PKCE
#  code_verifier=$(openssl rand -base64 96 | tr -d '+/=' | tr -d '\n' | cut -c -128)
#  code_challenge=$(echo -n "$code_verifier" |
#    openssl dgst -sha256 -binary | openssl base64 |
#    tr '+/' '-_' | tr -d '=' | tr -d '\n')

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
  # url="${url}&code_challenge=${code_challenge}&code_challenge_method=S256"

  echo "Browser Url: ${url}"
  open "$url"

  read -p "Paste the authorization code here: " authCode

  # export for next step
  export VC_REDIRECT_URI="${redirect_uri}"
  export VC_AUTH_CODE="${authCode}"
#  export VC_CODE_VERIFIER="${code_verifier}"
}

kc_token_request() {
  local realm="$1"

  cid=$(kcadm get clients -r "${realm}" -q clientId="${client_id}" --fields id --format csv --noquotes)
  client_secret=$(kcadm get "clients/${cid}/client-secret" -r "${realm}" | jq -r .value)

  local tokenUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/token"

  tokens=$(curl -s -X POST "$tokenUrl" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${client_id}" \
    -d "client_secret=${client_secret}" \
    -d "code=${VC_AUTH_CODE}" \
    -d "redirect_uri=${VC_REDIRECT_URI}")
    # -d "code_verifier=${VC_CODE_VERIFIER}")

  # Show raw tokens
  echo "Token Response ..."
  echo "${tokens}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokens}" | jq -r .access_token)
  export VC_ACCESS_TOKEN="${access_token}"
}

kc_credential_request() {
  local realm="$1"
  local credential_id="$2"

  local nonceUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/nonce"
  c_nonce=$(curl -s -X POST "${nonceUrl}" | jq -r '.c_nonce')

  holder_proof_json=".secret/es256-proof_holder.json"
  holder_proof_jwk=".secret/es256-holder-key.jwk"
  holder_proof_jwt=".secret/es256-proof_holder.jwt"

  mkdir -p ".secret"

  # 1) Proof payload
  holder_proof_json=".secret/proof_holder.json"
  cat > "${holder_proof_json}" <<-EOF
  {
    "aud": "${AUTH_SERVER_URL}/realms/${realm}",
    "iat": $(date +%s),
    "nonce": "${c_nonce}"
  }
EOF

  # 2) Build protected header template with typ, alg, and *public* JWK
  #    (remove private params from the JWK before embedding)
  pub_jwk=$(jq 'del(.d,.p,.q,.dp,.dq,.qi)' "${holder_proof_jwk}")

  sig_tpl_file=".secret/proof_sig_tpl.json"
  jq -n --argjson jwk "${pub_jwk}" \
    '{protected: {alg:"ES256", typ:"openid4vci-proof+jwt", jwk:$jwk}}' \
    > "$sig_tpl_file"

  # 3) Sign the proof (compact JWS)
  jose jws sig \
    -I "${holder_proof_json}" \
    -k "${holder_proof_jwk}" \
    -s "${sig_tpl_file}" \
    -o "${holder_proof_jwt}" \
    -c

  # 4) Credential request body (use **credential_configuration_id**)
  req_body=$(jq -n \
    --arg cid "${credential_id}" \
    --arg proof "$(cat ${holder_proof_jwt})" \
    '{
      credential_configuration_id: $cid,
      proofs: { jwt: [ $proof ] }
    }')

  echo "==== Credential Request Body ====" >&2
  echo "${req_body}" | jq . >&2
  echo "================================" >&2

  resp_json="$(curl -s -X POST "${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/credential" \
      -H "Authorization: Bearer ${VC_ACCESS_TOKEN}" \
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

  # If you have the issuer's public JWK:
  #jose jws ver -i "$VC_JWT" -k issuer-public.jwk -O- | jq .

  # If you only have the private JWK from Keycloak (admin side), derive the public part:
  #jose jwk pub -i es256-vc-signing-private.jwk -o issuer-public.jwk
  # or extract a key from a cert/PEM:
  #jose jwk exc -i issuer-cert.pem -o issuer-public.jwk
}
