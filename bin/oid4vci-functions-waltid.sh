#!/usr/bin/env bash

## Gets the wallet Id for an authenticated account
#
# https://wallet.demo.walt.id/swagger/index.html#/Accounts/get_wallet_api_wallet_accounts_wallets
get_wallet_id() {
  local token="$1"

  local wid status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -L "${WALLET_API_URL}/wallet-api/wallet/accounts/wallets" \
    -H "Authorization: Bearer ${token}")

  if [[ "$status" -eq 200 ]]; then
    wid=$(jq -r '.wallets[0].id' "${response}")
    rm -f "${response}"
  else
    echo "Getting wallet id failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi

  echo "Wallet Id: ${wid}" >&2

  # Return the walletId
  echo "${wid}"
}

load_or_generate_key() {
  local role="$1"

  mkdir -p ".secret"
  keyFile="es256-${role}-key.jwk"
  if [ ! -f ".secret/${keyFile}" ]; then
    echo "Creating key ${keyFile}" >&2
    jose jwk gen -i '{"alg":"ES256","crv":"P-256","use":"sig"}' -o ".secret/${keyFile}"
    thumbprint=$(jose jwk thp -i ".secret/${keyFile}")
    jq --arg kid "$thumbprint" '. + {kid: $kid}' ".secret/${keyFile}" > ".secret/${keyFile}.tmp"
    if [ -s ".secret/${keyFile}.tmp" ]; then
      mv ".secret/${keyFile}.tmp" ".secret/${keyFile}"
    fi
  else
    echo "Using key ${keyFile}" >&2
  fi

  # Return keyFile location
  echo ".secret/${keyFile}"
}

setup_waltid_issuer() {
  local name="$1" email="$2" password="$3"
  setup_waltid_user "issuer" "${name}" "${email}" "${password}"
}

setup_waltid_holder() {
  local name="$1" email="$2" password="$3"
  setup_waltid_user "holder" "${name}" "${email}" "${password}"
}

setup_waltid_verifier() {
  local name="$1" email="$2" password="$3"
  setup_waltid_user "verifier" "${name}" "${email}" "${password}"
}

## Register/Login role, create key and did:key (on demand)
#
setup_waltid_user() {
  local role="$1" name="$2" email="$3" password="$4"

  # Create/Login Issuer in WaltId Wallet API
  #
  token=$(wallet_auth_register_or_login "${name}" "${email}" "${password}") || exit 1
  if [[ -z "${token}" ]]; then
    echo "No auth token" >&2
    return 1
  fi
  
  ## Get the Issuer's wallet id
  #
  wid=$(get_wallet_id "${token}")
  if [[ -z "${wid}" ]]; then
    echo "No wallet id" >&2
    return 1
  fi
  
  ## Create/Import the Issuer's private key
  #
  jwk=$(cat "$(load_or_generate_key "${role}")")
  kid=$(wallet_keys_import "${token}" "${wid}" "${jwk}")
  if [[ -z "${kid}" ]]; then
    echo "No key id" >&2
    return 1
  fi
  
  ## Create/Import the Issuer's private key
  #
  did=$(wallet_dids_create "${token}" "${wid}" "${kid}")
  if [[ -z "${did}" ]]; then
    echo "No did:key" >&2
    return 1
  fi


  jq -n \
    --arg role "${role}" \
    --arg name "${name}" \
    --arg email "${email}" \
    --arg password "${password}" \
    --arg wid "${wid}" \
    --arg kid "${kid}" \
    --arg did "${did}" \
    '{role: $role, name: $name, email: $email, password: $password, wid: $wid, kid: $kid, did: $did}' > ".secret/${role}-details.json"

  return 0
}

## User login (type email)
#
# https://wallet.demo.walt.id/swagger/index.html#/Authentication/post_wallet_api_auth_login
wallet_auth_login() {
  local email="$1" password="$2"

  local token status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -L "${WALLET_API_URL}/wallet-api/auth/login" \
    -H "Content-Type: application/json" \
    --data @- <<-EOF
    {
      "type": "email",
      "email": "${email}",
      "password": "${password}"
    }
EOF
)

  if [[ "$status" -eq 200 ]]; then
    echo "Login for ${email} ok" >&2
    token=$(jq -r '.token' "${response}")
    rm -f "${response}"
  else
    echo "Login failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi

  echo "$token"
}

## Register a role (type email) if not registered already
#
# https://wallet.demo.walt.id/swagger/index.html#/Authentication/post_wallet_api_auth_register
wallet_auth_register() {
  local name="$1" email="$2" password="$3"

  local status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -L "${WALLET_API_URL}/wallet-api/auth/register" \
    -H "Content-Type: application/json" \
    --data @- <<-EOF
    {
      "type": "email",
      "name": "${name}",
      "email": "${email}",
      "password": "${password}"
    }
EOF
)

  if [[ "$status" -eq 201 ]]; then
    echo "Registration for ${email} ok" >&2
    rm -f "${response}"
    return 0
  elif [[ "$status" -eq 409 ]]; then
    echo "User ${email} already registered" >&2
    rm -f "${response}"
    return 0
  else
    echo "Registration failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi
}

## Register role on-demand, then login
#
wallet_auth_register_or_login() {
  local name="$1" email="$2" password="$3"
  local token

  # Attempt registration
  if ! wallet_auth_register "${name}" "${email}" "${password}"; then
    return $?
  fi

  # On successful registration or already registered
  if ! token="$(wallet_auth_login "$email" "$password")"; then
    return $?
  fi

  if [[ -z "${token}" ]]; then
    echo "Empty token after login" >&2
    return 1
  fi

  # Return the token to the caller
  echo "${token}"
}

## Create a did:key in the given wallet
#
# https://wallet.demo.walt.id/swagger/index.html#/DIDs/post_wallet_api_wallet__wallet__dids_create_key
wallet_dids_create() {
  local token="$1" wid="$2" kid="$3"

  local did status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -X POST \
    -L "${WALLET_API_URL}/wallet-api/wallet/${wid}/dids/create/key?keyId=${kid}&useJwkJcsPub=true" \
    -H "Authorization: Bearer ${token}")

  if [[ "$status" -eq 200 ]]; then
    did=$(cat "${response}")
    echo "DID created: ${did}" >&2
    rm -f "${response}"
  elif [[ "$status" -eq 409 ]]; then
    did=$(wallet_dids_find "${token}" "${wid}" "${kid}")
    rm -f "${response}"
  else
    echo "DID creation failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi

  # Return the DID
  echo "${did}"
}

## Find an already existing did:key for the given wallet
#
# https://wallet.demo.walt.id/swagger/index.html#/DIDs/get_wallet_api_wallet__wallet__dids
wallet_dids_find() {
  local token="$1" wid="$2" kid="$3"

  local did status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -L "${WALLET_API_URL}/wallet-api/wallet/${wid}/dids" \
    -H "Authorization: Bearer ${token}")

  if [[ "$status" -eq 200 ]]; then
    did=$(jq -r --arg kid "$kid" '.[] | select(.keyId==$kid) | .did' "${response}")
    echo "${did}" >&2
    rm -f "${response}"
  else
    echo "Getting DID failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi

  # Return the DID
  echo "${did}"
}

## Import a key to the given wallet
#
# https://wallet.demo.walt.id/swagger/index.html#/Keys/post_wallet_api_wallet__wallet__keys_import
wallet_keys_import() {
  local token="$1" wid="$2" jwk="$3"

  local kid status response
  response=$(mktemp)

  status=$(curl -s -o "${response}" -w "%{http_code}" \
    -L "${WALLET_API_URL}/wallet-api/wallet/${wid}/keys/import" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data "${jwk}")

  if [[ "$status" -eq 201 ]]; then
    kid=$(cat "${response}")
    echo "Key import ok: ${kid}" >&2
    rm -f "${response}"
  elif [[ "$status" -eq 409 ]]; then
    kid=$(jq -r '.message | capture("Key with ID (?<kid>\\S+) already exists").kid' "${response}")
    echo "Key already exists: ${kid}" >&2
    rm -f "${response}"
  else
    echo "Key import failed with ${status}" >&2
    cat "${response}" >&2
    rm -f "${response}"
    return 1
  fi

  # Return the keyId
  echo "${kid}"
}
