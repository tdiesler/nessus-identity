# OpenId Foundation Conformance Suite on Keycloak  

The primary documentation of how to build & run the testsuite is [here](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run)

To make this work, we need to run Keycloak behind a reverse proxy - see the [Console Readme](../console/README.md) on how to install/configure Nginx as that proxy.

## Run Keycloak

There is a target in the Makefile

```shell
make keycloak-run-proxy
```

Then open an SSH tunnel like this

```shell
ssh -R 127.0.0.1:8080:localhost:8080 core@vps4c.eu.ebsi
```

It should now be possible to access Keycloak on: https://keycloak.nessustech.io:8443

## Import the test realm

We have a Keycloak `oid4vci-setup.sh` script that we can use to prepare the Issuer for OpenID Conformance testing.

```
TARGET=proxy ./bin/oid4vci-setup.sh --force
```

You should now be able to access the Client Attester JWKS at: https://keycloak.nessustech.io:8443/realms/oid4vci/client-attester/jwks

## Run the Conformance Test Suite

Clone the project, build it and run it on docker

```shell
git clone https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
mvn clean package

docker compose -f docker-compose-dev-mac.yml up
```

It should now be possible to access the Conformance Suite on: https://localhost:8443

### Configure the HAIP Issuer Test Plan

| Test Plan         | OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test an issuer |
| Credential Format | sd_jwt_vc |
| Code Flow Variant | wallet_initiated |

Then add a config like this ...

```json
{
    "alias": "keycloak-preview",
    "vci": {
        "credential_issuer_url": "https://keycloak.nessustech.io:8443/realms/oid4vci",
        "credential_configuration_id": "oid4vc_natural_person_sd"
    },
    "client2": {
        "client_id": "oid4vci-client"
    }
}
```

which you can also find in this directory.

## HAIP Conformance Status

Conformance status is tracked by: [Keycloak Conformance with HAIP Profile](https://github.com/tdiesler/nessus-identity/issues/354)

