# OpenId Foundation Conformance Suite on Keycloak  

The primary documentation of how to build & run the testsuite is [here](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run)

To make this work, we need to run Keycloak behind a reverse proxy - see the [Console Readme](../console/README.md) on how to install/configure Nginx as that proxy.

## Run Keycloak

We can run Keycloak ...

* locally and accessible through a reverse proxy (TARGET=proxy)
* locally and accessible through ngrok (TARGET=ngrok)
* remotely with direct access from Cloudflare (TARGET=stage)

### Keycloak behind NGINX reverse proxy

```shell
make keycloak-build keycloak-run-proxy
```

Then open an SSH tunnel like this

```shell
ssh -R 127.0.0.1:8080:localhost:8080 core@vps4c.eu.ebsi
```

It should now be possible to access Keycloak on: https://keycloak.nessustech.io:8443

### Keycloak behind ngrok

The `ngrok` target runs Keycloak locally and exposes it through a ngrok HTTPS
tunnel. The conformance suite uses the ngrok URL as the issuer base URL.

Start ngrok against the local Keycloak HTTP port:

```shell
ngrok http 8080
export NGROK_URL="$(curl -fsS http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[] | select(.proto=="https") | .public_url' | head -n 1)"
```

Run Keycloak locally with the public ngrok URL as its hostname:

```shell
make keycloak-build
make keycloak-build keycloak-run-ngrok
```

Put the freshly built Keycloak admin CLI on the path and import the conformance
realm. The `ngrok` target uses `admin` / `admin` for the local Keycloak admin
user by default and `https://waltid-wallet-api.localtest.me` for WaltID.

```shell
TARGET=ngrok ./scripts/oid4vci-setup.sh --force
```

### Keycloak on Kubernetes

Build and deploy the Keycloak image

```shell
TARGET=stage make keycloak-image
helm upgrade --kube-context=ebsi --install nessus-identity ./helm -f ./helm/values-services-stage.yaml
```

In this setup Traefik is the TLS terminating edge.
Client ⇒ Cloudflare ⇒ Traefik ⇒ Keycloak

The minimum TLS version that Cloudflare accepts needs to be configured with Cloudflare.
After receiving the client request, Cloudflare establishes a new TLS connection, which is always > TLS-1.0

SSL/TLS → Edge Certificates → Minimum TLS Version

Also configure these ciphers

- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

It should now be possible to access Keycloak on: https://keycloak.nessustech.io

## Import the test realm

We have a `oid4vci-setup.sh` script that we can use to prepare the Issuer for OpenID Conformance testing.

```
TARGET=proxy ./scripts/oid4vci-setup.sh 
```

For `TARGET=ngrok`:

```shell
TARGET=ngrok NGROK_URL="${NGROK_URL}" ./scripts/oid4vci-setup.sh --force
```

For mdoc issuer tests, add `--mdoc` when importing the realm for the target:

```shell
TARGET=proxy ./scripts/oid4vci-setup.sh --force --mdoc
TARGET=ngrok NGROK_URL="${NGROK_URL}" ./scripts/oid4vci-setup.sh --force --mdoc
```

Add `--skip-wallet` when only Keycloak conformance setup is needed and WaltID is
not available. This writes local placeholder DID details for the Keycloak users
and skips the sample credential fetch.

```shell
TARGET=ngrok NGROK_URL="${NGROK_URL}" ./scripts/oid4vci-setup.sh --force --mdoc --skip-wallet
```

## Run the Conformance Tests in UI

Clone the project, build it and run it on docker

```shell
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
mvn clean package

docker compose -f docker-compose-dev-mac.yml up --detach
```

It should now be possible to access the Conformance Suite on: https://localhost:8443

### Configure the HAIP Issuer Test Plan

| Field             | Value                                                     |
|-------------------|-----------------------------------------------------------|
| Specification     | OID4VCI                                                   |
| Entity Under Test | Test a OpenID4VCI issuer                                  |
| Test Plan         | OpenID for Verifiable Credential Issuance 1.0 Final/HAIP  |
| Credential Format | sd_jwt_vc                                                 |
| Code Flow Variant | wallet_initiated                                          |

For mdoc issuance, use the same issuer HAIP test plan with:

| Field             | Value                                                     |
|-------------------|-----------------------------------------------------------|
| Specification     | OID4VCI                                                   |
| Entity Under Test | Test an OpenID4VCI issuer                                 |
| Test Plan         | OpenID for Verifiable Credential Issuance 1.0 Final/HAIP  |
| Credential Format | mdoc                                                      |
| Code Flow Variant | wallet_initiated                                          |

Then add a config like the one you can find in this directory.

## Run the Conformance Tests automated

### Setup the Python3 environment

```shell
cd conformance-suite/scripts
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run a given test

First, try to run the first test in the plan - the result should look like this.

<img src="docs/img/oid4vci-1_0-issuer-metadata-test.png" width="800"/>

Next, try to run the same test from the python script

```shell
CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443"
NESSUS_IDENTITY_DIR="/path/to/nessus-identity"
CONFIG_FILE="${NESSUS_IDENTITY_DIR}/scripts/config/keycloak-openid-issuer-config.json"
PLAN_VARIANTS="[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]"
./run-test-plan.py --no-parallel "oid4vci-1_0-issuer-haip-test-plan${PLAN_VARIANTS}:oid4vci-1_0-issuer-metadata-test,oid4vci-1_0-issuer-metadata-test-signed" "${CONFIG_FILE}"
```

### Run a profile

Run one of the configured profiles:

```shell
./scripts/openid-conformance.sh --run-profile issuer
./scripts/openid-conformance.sh --run-profile verifier
./scripts/openid-conformance.sh --run-profile fapi2-user-rejects-authentication
./scripts/openid-conformance.sh --run-profile oid4vci-mdoc-issuance
```

The mdoc issuer profile runs the issuer metadata tests and the issuer happy-flow
module for the `org.iso.18013.5.1.mDL` credential configuration. Override the
credential configuration when the imported realm uses a different id:

```shell
MDOC_CREDENTIAL_CONFIGURATION_ID="your-mdoc-config-id" \
./scripts/openid-conformance.sh --run-profile oid4vci-mdoc-issuance
```

## HAIP Conformance Status

Conformance status is tracked by: [Conformance with OpenID HAIP Profile](https://github.com/keycloak/keycloak/issues/47149)
