#!/usr/bin/env bash

# Log in as Keycloak Admin
#
kc_admin_login() {

  kubecmd="kubectl --context ${KUBE_CONTEXT}"
  adminUser=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_USERNAME}' | base64 -d)
  adminPass=$(${kubecmd} get secret keycloak-admin -o jsonpath='{.data.ADMIN_PASSWORD}' | base64 -d)

  kcadm config credentials --server "${AUTH_SERVER_URL}" --realm master \
      --user "${adminUser}" --password "${adminPass}"
}

kc_authorization_request() {
  local realm="$1"

  local response_type="code"
  local client_id="vc-issuer"
  local redirect_uri="urn:ietf:wg:oauth:2.0:oob"
  local credential_id="oid4vc_natural_person"

  cid=$(kcadm get clients -r "${realm}" -q clientId="${client_id}" --fields id --format csv --noquotes)
  client_secret=$(kcadm get "clients/${cid}/client-secret" -r "${realm}" | jq -r .value)

  # PKCE
  code_verifier=$(openssl rand -base64 96 | tr -d '+/=' | tr -d '\n' | cut -c -128)
  code_challenge=$(echo -n "$code_verifier" |
    openssl dgst -sha256 -binary | openssl base64 |
    tr '+/' '-_' | tr -d '=' | tr -d '\n')

  scopes="openid"
  # scopes=$(printf 'openid %s' "${credential_id}" | jq -sRr @uri)

  local authUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/auth"

  # Build JSON for authorization_details
  authorization_details=$(printf '{
    "type": "openid_credential",
    "credential_configuration_id": "%s"
  }' "${credential_id}" | jq -sRr @uri)

  url="${authUrl}?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}"
  url="${url}&scope=${scopes}&authorization_details=${authorization_details}"
  url="${url}&code_challenge=${code_challenge}&code_challenge_method=S256"

  echo "Opening URL: ${url}" >&2
  open "$url"

  read -p "Paste the authorization code here: " authCode
  echo "${authCode}"

  # export for next step
  export VC_CLIENT_ID="${client_id}"
  export VC_CLIENT_SECRET="${client_secret}"
  export VC_REDIRECT_URI="${redirect_uri}"
  export VC_AUTH_CODE="${authCode}"
  export VC_CODE_VERIFIER="${code_verifier}"
}

kc_token_request() {
  local realm="$1"

  local client_id="vc-issuer"
  local tokenUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/openid-connect/token"

  tokens=$(curl -s -X POST "$tokenUrl" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code" \
    -d "client_id=${VC_CLIENT_ID}" \
    -d "client_secret=${VC_CLIENT_SECRET}" \
    -d "code=${VC_AUTH_CODE}" \
    -d "redirect_uri=${VC_REDIRECT_URI}" \
    -d "code_verifier=${VC_CODE_VERIFIER}")

  # Show raw tokens
  echo "${tokens}" | jq . >&2

  # Extract access_token
  access_token=$(echo "${tokens}" | jq -r .access_token)
  export VC_ACCESS_TOKEN="${access_token}"
}

kc_get_credential() {
  local realm="$1"
  local credential_id="oid4vc_natural_person"

  local nonceUrl="${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/nonce"

  # echo "nonceUrl: ${nonceUrl}" >&2
  c_nonce=$(curl -s -X POST "${nonceUrl}" | jq -r '.c_nonce')
  echo "c_nonce: ${c_nonce}" >&2

  # [TODO] Read Holder's DID from somewhere
  holder_did="did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbpBwbYkffQJfLUSpSiiK9j7hBRnSimcPiavVb5xFWvanTdaX2bi68wnjhcxBFuzUotsLX5iWnjswmAXH3uN1WSScUDeU88pE2TDhWSbzDoS3pH3jQUgcpu7N4NAKPjynR4g"
  holder_proof_json=".secret/proof_holder.json"
  holder_proof_jwt=".secret/proof_holder.jwt"

  cat > "${holder_proof_json}" <<-EOF
  {
    "iss": "${holder_did}",
    "aud": "${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/credential",
    "iat": $(date +%s),
    "nonce": "${c_nonce}"
  }
EOF

  jose jws sig -I "${holder_proof_json}" -k ".secret/secp256r1-holder-key.jwk" -o "${holder_proof_jwt}" -c

  # format: "dc+sd-jwt",

  req_body=$(jq -n \
    --arg cid "${credential_id}" \
    --arg proof "$(cat ${holder_proof_jwt})" \
    '{
      credential_configuration_id: $cid,
      proofs: { jwt: [$proof] }
    }')

  echo "==== Credential Request Body ====" >&2
  echo "${req_body}" | jq . >&2
  echo "================================" >&2

  curl -s -X POST "${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/credential" \
      -H "Authorization: Bearer ${VC_ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "${req_body}" | jq .
}

kc_oid4vci_realm_create() {
  local realm="$1"
  local force="$2"

  # Check if realm already exists
  #
  realm_exists=$(kcadm get realms | jq -e ".[] | select(.realm==\"${realm}\")" >/dev/null 2>&1 && echo true || echo false)
  if [[ $realm_exists == true ]]; then
    if [[ ${force} == true ]]; then
      kcadm delete "realms/${realm}"
      echo "Deleting realm '${realm}'"
    else
      echo "Realm '${realm}' already exists"
      return 0
    fi
  fi
  
  # Create realm
  #
  kcadm create realms -s realm="${realm}" -s enabled=true
  
  # Create Issuer User
  #
  kc_user_create "${realm}" "${ISSUER_NAME}" "${ISSUER_EMAIL}" "${ISSUER_PASSWORD}"
  
  # Configure oid4vci signing key
  #
  echo "Configure OID4VCI signing key"
  
  jwk_json=$(jq -c . ".secret/secp256r1-issuer-key.jwk" | jq -Rs .)
  kcadm update "realms/${realm}" -f - <<-EOF
  {
    "attributes": {
      "oid4vci.signing_keys": $jwk_json
    }
  }
EOF
  
  # Configure oid4vci realm attributes
  #
  echo "Configure OID4VCI realm attributes"
  
  kcadm update "realms/${realm}" -r master -f - <<-EOF
  {
    "attributes": {
      "oid4vci.vc_formats": "dc+sd-jwt",
      "oid4vci.issuer_metadata_endpoint": "${AUTH_SERVER_URL}/realms/${realm}/.well-known/openid-credential-issuer"
    }
  }
EOF
  
  # Create a client for credential issuance
  #
  kcadm create clients -r "${realm}" -s clientId=vc-issuer -s enabled=true \
      -s redirectUris='["https://app.example.com/callback", "urn:ietf:wg:oauth:2.0:oob"]' \
      -s authorizationServicesEnabled=true \
      -s directAccessGrantsEnabled=true \
      -s serviceAccountsEnabled=true \
      -s publicClient=false \
      -s 'attributes."oid4vci.enabled"=true'
  
  # Associate client with appropriate protocol
  #
  clientId=$(kcadm get clients -r "${realm}" -q clientId=vc-issuer 2>/dev/null | jq -r -j '.[0].id')
  kcadm create "clients/${clientId}/protocol-mappers/models" -r ${realm} -f - <<-EOF
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
}

kc_user_create() {
  local realm="$1"
  local userName="$2"
  local userEmail="$3"
  local userPassword="$4"

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
    echo "Creating user '${userName}' in realm '${realm}'" >&2
    kcadm create users -r "${realm}" \
      -s username="${lowerName}" \
      -s email="${userEmail}" \
      -s firstName="${firstName}" \
      -s lastName="${lastName}" \
      -s emailVerified=true \
      -s enabled=true

    kcadm set-password -r "${realm}" --username "${lowerName}" --new-password "${userPassword}" --temporary=false
  fi
}
