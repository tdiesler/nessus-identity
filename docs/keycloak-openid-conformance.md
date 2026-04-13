# OpenId Foundation Conformance Suite on Keycloak  

The primary documentation of how to build & run the testsuite is [here](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run)

To make this work, we need to run Keycloak behind a reverse proxy - see the [Console Readme](../console/README.md) on how to install/configure Nginx as that proxy.

## Run Keycloak

We can run Keycloak ...

* locally and accessible through a reverse proxy (TARGET=local)
* remotely with direct access from Cloudflare (TARGET=stage)

### Keycloak behind NGINX reverse proxy

```shell
make keycloak-run-proxy
```

Then open an SSH tunnel like this

```shell
ssh -R 127.0.0.1:8080:localhost:8080 core@vps4c.eu.ebsi
```

It should now be possible to access Keycloak on: https://keycloak.nessustech.io:8443

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
CONFIG_FILE="${HOME}/git/nessus-identity/docs/keycloak-openid-conformance-config.json"
PLAN_VARIANTS="[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]"
./run-test-plan.py --no-parallel "oid4vci-1_0-issuer-haip-test-plan${PLAN_VARIANTS}:oid4vci-1_0-issuer-metadata-test,oid4vci-1_0-issuer-metadata-test-signed" "${CONFIG_FILE}"
```

## HAIP Conformance Status

Conformance status is tracked by: [Conformance with OpenID HAIP Profile](https://github.com/keycloak/keycloak/issues/47149)

