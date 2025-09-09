package io.nessus.identity.types

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.matchers.equals.shouldBeEqual
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test

class CredentialOfferTypeTest {

    val log = KotlinLogging.logger {}

    @Test
    fun testCredentialOfferDraft11() {

        // Sent by EBSI CT v3.2
        val expJson = Json.decodeFromString<JsonObject>("""
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
                "CTWalletSameAuthorisedInTime"
              ]
            }
          ],
          "grants": {
            "authorization_code": {
              "issuer_state": "eyJhbGciOi...yM0mRemu9Q"
            }
          }
        }            
        """)

        // Serialize to WaltId CredentialOffer
        val waltIdOffer = id.walt.oid4vc.data.CredentialOffer.fromJSON(expJson)
        var wasJson = waltIdOffer.toJSON()

        log.info { expJson }
        log.info { wasJson }
        wasJson.shouldBeEqual(expJson)

        // Serialize to our CredentialOfferDraft11
        val draft11 = CredentialOfferDraft11.fromJson(expJson)
        wasJson = draft11.toJsonObj()

        log.info { wasJson }
        wasJson.shouldBeEqual(expJson)

        // Convert to WaltId CredentialOffer
        wasJson = draft11.toWaltIdCredentialOffer().toJSON()

        log.info { wasJson }
        wasJson.shouldBeEqual(expJson)
    }
}
