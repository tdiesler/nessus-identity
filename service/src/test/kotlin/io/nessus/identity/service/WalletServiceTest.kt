package io.nessus.identity.service

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantDetails
import io.kotest.common.runBlocking
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.nessus.identity.types.IssuerMetadataDraft11
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Test

class WalletServiceTest : AbstractServiceTest() {

    @Test
    fun decodeCredentialOffer() {
        val credOfferJson = """
        {
          "credential_issuer": "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock",
          "credentials": [
            {
              "format": "jwt_vc",
              "trust_framework": {
                "name": "ebsi",
                "type": "Accreditation",
                "uri": "TIR link towards accreditation"
              },
              "types": [
                "VerifiableCredential",
                "VerifiableAttestation",
                "CTWalletSamePreAuthorisedInTime"
              ]
            }
          ],
          "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": "eyJhbGciOiJFUzI1NiIsImtpZCI6IlQ2aVBNVy1rOE80dXdaaWQyOUd3TGUtTmpnNDBFNmpOVDdoZExwSjNaU2ciLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE3NDkwNDM3ODMsImV4cCI6MTc0OTA0NDA4MywiYXVkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2siLCJhdXRob3JpemF0aW9uX2RldGFpbHMiOlt7ImZvcm1hdCI6Imp3dF92YyIsImxvY2F0aW9ucyI6WyJodHRwczovL2FwaS1jb25mb3JtYW5jZS5lYnNpLmV1L2NvbmZvcm1hbmNlL3YzL2lzc3Vlci1tb2NrIl0sInR5cGUiOiJvcGVuaWRfY3JlZGVudGlhbCIsInR5cGVzIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIiwiQ1RXYWxsZXRTYW1lUHJlQXV0aG9yaXNlZEluVGltZSJdfV0sImNsaWVudF9pZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib3QzWWo4VWRQZVdRWUxNVmF1Uk13UlMxVGFEd3A1MjRQYVR0YndBYkROalhrWEhURHozb0pUU0hOTm9ZZThveWFkZGZQSmdoekpZaVVoR045THdmaTV2elpkZDRDTnk3dkJuS0hZMVdyRXFodndnajNKSHplN2d3U3dZQzhBUUFzVyIsImlzcyI6Imh0dHBzOi8vYXBpLWNvbmZvcm1hbmNlLmVic2kuZXUvY29uZm9ybWFuY2UvdjMvaXNzdWVyLW1vY2siLCJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm90M1lqOFVkUGVXUVlMTVZhdVJNd1JTMVRhRHdwNTI0UGFUdGJ3QWJETmpYa1hIVER6M29KVFNITk5vWWU4b3lhZGRmUEpnaHpKWWlVaEdOOUx3Zmk1dnpaZGQ0Q055N3ZCbktIWTFXckVxaHZ3Z2ozSkh6ZTdnd1N3WUM4QVFBc1cifQ.pkQ0Jt8QISwTdIKJPissikyQGk2Apy0uPYUleC57zf-M9ieqhvkfMlTtHJNKwrUAJE-orRkXhobCDasUan0Qxw",
              "user_pin_required": true
            }
          }
        }            
        """.trimIndent()

        val credOffer = CredentialOffer.fromJSONString(credOfferJson) as CredentialOffer.Draft11

        credOffer.credentials.shouldHaveSize(1)
        credOffer.grants.shouldHaveSize(1)

        val credential = credOffer.credentials[0].jsonObject
        credential["format"]?.jsonPrimitive?.content shouldBe "jwt_vc"

        val grant = credOffer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] as GrantDetails
        grant.preAuthorizedCode.shouldNotBeBlank()
        grant.userPinRequired shouldBe true
    }

    @Test
    fun resolveIssuerMetadata() {
        runBlocking {
            val metadataUrl = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
            val metadata = OID4VCIUtils.resolveIssuerMetadata(metadataUrl) as IssuerMetadataDraft11
            metadata.credentialsSupported.shouldNotBeNull()
        }
    }
}
