## Nessus Identity

Nessus Identity is about Digital Identity and Verifiable Credentials.

[<img src="docs/img/ssi-book.png" height="200" alt="self sovereign identity">](https://www.manning.com/books/self-sovereign-identity)

This project now primarily targets the [European Blockchain Services Infrastructure (EBSI)](https://ec.europa.eu/digital-building-blocks/sites/display/EBSI/Home).

We aim to provide a backend wallet infrastructure for issuer, holder, verifier for EBSI conformant verifiable credentials. 
We already pass the [EBSI Wallet Conformance](https://hub.ebsi.eu/wallet-conformance) testsuite in version v3.2. The next step will be to focus
on Keycloak as the credential issuer and pass the upcoming [Conformance Tests v4.0 ](https://hub.ebsi.eu/conformance/standards-versions)

Once this is done, we can think about whether/how we can integrate that with [Apache Camel](https://camel.apache.org/) and
hence offer our large user/customer base an important additional piece of functionality for their integration tasks.

Our greater vision is, that integration endpoints can have "Trust over IP" by using standard verifiable credentials.

## Getting Started

All services run in Kubernetes. For local test environment you could for example use [Rancher Desktop](https://rancherdesktop.io/).

Before you install the services for the first time, you will need to build the docker images and 
[prepare](./PREPARE.md) the K8S environment.

Then install the services run ...

```
helm upgrade --install nessus-identity ./helm -f ./helm/values-services-dev.yaml
```

Check in [Lens](https://k8slens.dev/) that all pods are running and then do a one-time setup step for 
the OpenID for Verifiable Credential Issuance ([OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)) 
realm in Keycloak.

```
./bin/oid4vci-setup.sh
```

If all goes well, this will ... 

* Create a Key and DID for the Issuer, Holder and Verifier (Max, Alice, Bob)
* Create OID4VCI Realm in Keycloak
* Add a Verifiable Credential definition to the OID4VCI Realm
* Attempt to issue the VC to Alice (give your consent with alice/password)

You should now also be able to access the Issuer's configuration [here](https://oauth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer)

To run the console app ...

```
make run-services
```

