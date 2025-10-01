package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows


class IssuerServiceKeycloakTest : AbstractServiceTest() {

    lateinit var max: OIDContext
    lateinit var alice: OIDContext

    lateinit var issuerSvc: IssuerServiceKeycloak
    lateinit var walletSvc: WalletServiceKeycloak

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            // Create the Issuer's OIDC context (Max is the Issuer)
            max = OIDContext(login(Max).withDidInfo())
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(login(Alice).withDidInfo())
            walletSvc = WalletService.createKeycloak()
        }
    }

    @Test
    fun testGetIssuerMetadata() {
        /*
            Credential Issuer Metadata
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

            Issuer Metadata Endpoints
            https://oauth.localtest.me/realms/oid4vci/.well-known/openid-configuration
            https://oauth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
        */
        runBlocking {

            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    fun testCreateCredentialOffer() {
        /*
            Credential Offer Endpoint
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        */
        runBlocking {

            issuerSvc.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))

            assertThrows<IllegalArgumentException> {
                issuerSvc.createCredentialOffer(max, alice.did, listOf("oid4vc_unknown"))
            }
        }
    }

    @Test
    fun issueCredentialInTime() {
        /*
            Authorization Code Flow
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
        */
        runBlocking {

            val ctype = "oid4vc_identity_credential"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
            val credOffer = issuerSvc.createCredentialOffer(max, alice.did, listOf(ctype))

            val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
            val credObj = walletSvc.credentialFromOfferInTime(alice, credOffer, callbackHandler)
            val vc = credObj.getValue("vc").jsonObject
            log.info { "Credential: $vc" }

            val wasTypes = vc.getValue("type").jsonArray.map { it.jsonPrimitive.content }
            wasTypes shouldBeEqual credOffer.getTypes()

            val subject = vc.getValue("credentialSubject").jsonObject
            subject.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
            subject.getValue("id").jsonPrimitive.content shouldBeEqual alice.did
        }
    }
}