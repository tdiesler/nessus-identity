# Keycloak setup notes

## Build the nightly docs

```
mvn clean install -am -pl docs/documentation/dist -Pdocumentation

open docs/documentation/server_admin/target/generated-docs/index.html
```

## Issues to report

1. Documented [process for 26.3.4](https://www.keycloak.org/docs/latest/server_admin/index.html#define-realm-attributes)
   does not create [credential_configurations_supported](https://auth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer)

2. OIDC client attributes need to have oid4vci.enabled=true

3. oid4vc-subject-id-mapper produces literal 'id' 

    {
        "name" : "subjectId",
        "protocol" : "oid4vc",
        "protocolMapper" : "oid4vc-subject-id-mapper",
        "config" : {
          "claim.name" : "id"
        }
   }

4. Verify access via notification_id

   curl -s -X POST "${AUTH_SERVER_URL}/realms/${realm}/protocol/oid4vc/deferred_credential" \
   -H "Authorization: Bearer ${VC_ACCESS_TOKEN}" \
   -H "Content-Type: application/json" \
   -d '{"notification_id":"R8R5BIAt7Q..."}' | jq .

## Notes

With the current setup, the AuthorizationRequest as well as the TokenRequest are public.

Security relies on the authorization code flow:

* The code is short-lived.
* It is bound to the redirect_uri.
* It’s only given after Alice logs in (user authentication).

The authorization server (Keycloak) trusts that whoever presents the code is the legitimate client (public client assumption).

That’s why public clients are recommended only for “native apps / wallets” that can’t keep a secret.

But there are risks ...

1. Code interception:
    If someone steals Alice’s code before it’s exchanged, they can get the tokens.
    → That’s why PKCE is normally required (code_challenge + code_verifier).

2. Token replay:
    Access tokens can be reused until expiry.
    → You need to ensure TLS everywhere, and possibly use DPoP (proof-of-possession).

## Safer setup

* Enable PKCE on the Keycloak client (Authorization Code with PKCE required).
* Keep it public (no secret).
* Tokens are then bound to the code_verifier, so stealing just the code is not enough.
* For higher assurance, you can move toward private_key_jwt client auth later.