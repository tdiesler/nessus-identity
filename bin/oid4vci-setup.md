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