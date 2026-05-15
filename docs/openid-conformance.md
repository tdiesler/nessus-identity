# OpenId Foundation Conformance Suite on Keycloak  

The primary documentation of how to build & run the testsuite is [here](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run)

To make this work, we need to run Keycloak behind a reverse proxy - see the [Console Readme](../console/README.md) on how to install/configure Nginx as that proxy.

## Run Keycloak

We can run Keycloak ...

* locally behind NGROK (TARGET=ngrok)
* locally behind NGINX (TARGET=proxy)
* remotely nessustech.io (TARGET=stage)

Running Keycloak behind ngrok is the most convenient and works (reasonably) when running individual conformance modules
through the OpenID WebUI (see below). There is however an issue that NGROK allows ciphers reject by the HAIP-1.0 test profile.
Also, the automated test run seems to hit the NGROK paywall because of too many requests/min.

### Generate an x5c certificate for Keycloak

Install the local root CA

```shell
brew install mkcert
mkcert -install
```

Generate a certificate for Keycloak

```shell
mkcert -cert-file ".secret/keycloak-proxy.pem" -key-file ".secret/keycloak-proxy-key.pem" keycloak.nessustech.io
```

Build the x5c certificate chain

```shell
cat ".secret/keycloak-proxy.pem" "$(mkcert -CAROOT)/rootCA.pem" > ".secret/keycloak-proxy-chain.pem"
```


### Keycloak behind NGINX

NGINX is deployed as a standalone service on nessustech.io. In order to use this method you need to granted SSH access
to that server in order to open the tunnel. TODO: is there a way to tunnel access without general SSH access?

```shell
make keycloak-build keycloak-run-proxy
```

Then open an SSH tunnel like this

```shell
ssh -R 127.0.0.1:8080:localhost:8080 core@vps4c.eu.ebsi
```

It should now be possible to access Keycloak on: https://keycloak.nessustech.io:8443

Now, setup test oid4vci realm, which assumes that you have `kcadm` on your path.

```shell
TARGET=proxy ./scripts/oid4vci-setup.sh --force
```

### Keycloak behind NGROK

The `ngrok` target runs Keycloak locally and exposes it through a ngrok HTTPS
tunnel. The conformance suite uses the ngrok URL as the issuer base URL.

Start ngrok against the local Keycloak HTTP port:

```shell
ngrok http 8080
export NGROK_URL="$(curl -fsS http://127.0.0.1:4040/api/tunnels | jq -r '.tunnels[] | select(.proto=="https") | .public_url' | head -n 1)"
```

Run Keycloak locally with the public ngrok URL as its hostname:

```shell
make keycloak-build keycloak-run-ngrok
```

Now, setup test oid4vci realm, which assumes that you have `kcadm` on your path.

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

## Setup the oid4vci test realm

We have a `oid4vci-setup.sh` script that we can use to prepare the Issuer/Verifier for OpenID Conformance testing.

The `--force` option creates the `oid4vci` realm from scratch

```shell
TARGET=ngrok ./scripts/oid4vci-setup.sh --force
```

The `--mdoc` option enables that format

```shell
TARGET=ngrok ./scripts/oid4vci-setup.sh --mdoc
```

Add `--skip-wallet` when only Keycloak conformance setup is needed and WaltID is
not available. This writes local placeholder DID details for the Keycloak users
and skips the sample credential fetch.

## Run the Conformance Tests in UI

Clone the project, build it and run it on docker

```shell
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
mvn clean package

docker compose -f docker-compose-dev-mac.yml up
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

### Run a given test module or profile

First, try to run the first test through the WebUI - the result should look like this.

<img src="docs/img/oid4vci-1_0-issuer-metadata-test.png" width="800"/>

For automated test have a look at `./scripts/openid-conformance.sh --help`

At the time of writing the output looks like this ...

```shell
OpenID Conformance Suite target: proxy
Usage: openid-conformance [--clean] [--help] [--show-modules role] [--run role] [--run-module role module] [--run-profile name]

  --clean           Cleans existing test plans from the database
  --run-all         Run all profiles for a given role
  --run-module      Run a single test module
  --run-profile     Run the given test profile
  --show-client     Show the configuration for a given client
  --show-scope      Show the configuration for a given client scope
  --show-modules    Show effective test modules for a given role

  Roles
    - issuer        Issuer modules
    - verifier      Verifier modules

  Profiles
    - [1|issuer]                                              Run the default issuer profile
    - [2|verifier]                                            Run the default verifier profile
    - [3|fapi2-reused-request-uri-prior-to-auth-completion]   Server enforces one-time use of request_uri
    - [4|fapi2-user-rejects-authentication]                   User rejects consent during authentication
    - [5|oid4vci-mdoc-issuance]                               Run the mdoc issuer profile
    - [6|oid4vp-verifier-happy-flow]                          Run the OID4VP verifier happy-flow profile
```

## HAIP Conformance Status

Conformance status is tracked by: [Conformance with OpenID HAIP Profile](https://github.com/keycloak/keycloak/issues/47149)
