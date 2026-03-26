# OpenId Foundation Conformance Suite on Keycloak  

The primary documentation of how to build & run the testsuite is [here](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run)

To make this work, we need to run Keycloak behind a reverse proxy - see the [Console Readme](../console/README.md) on how to install/configure Nginx as that proxy.

## Run Keycloak

We can run Keycloak 

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

We have a Keycloak `oid4vci-setup.sh` script that we can use to prepare the Issuer for OpenID Conformance testing.

```
TARGET=stage ./bin/oid4vci-setup.sh 
```

## Run the Conformance Test Suite

Clone the project, build it and run it on docker

```shell
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
mvn clean package

docker compose -f docker-compose-dev-mac.yml up --detach
```

It should now be possible to access the Conformance Suite on: https://localhost:8443

### Configure the HAIP Issuer Test Plan

| Test Plan         | OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test an issuer |
| Credential Format | sd_jwt_vc |
| Code Flow Variant | wallet_initiated |

Then add a config like the one you can find in this directory.

## HAIP Conformance Status

Conformance status is tracked by: [[#354] Keycloak Conformance with HAIP Profile](https://github.com/tdiesler/nessus-identity/issues/354)

