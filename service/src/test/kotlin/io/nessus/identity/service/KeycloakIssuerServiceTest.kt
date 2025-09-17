package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.nessus.identity.extend.getRequestUrl
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class KeycloakIssuerServiceTest : AbstractIssuerServiceTest<CredentialOfferDraft17, IssuerMetadataDraft17>() {

    @BeforeEach
    fun setUp() {
        issuerSrv = IssuerService.createKeycloak()
    }

    @Test
    fun testGetCredentialOffer() {
        /*
            Credential Offer Endpoint
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        */
        runBlocking {

            // Issuer's OIDC context (Max is the Issuer)
            val max = OIDContext(setupWalletWithDid(Max))

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(setupWalletWithDid(Alice))

            issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))

            assertThrows<IllegalArgumentException> {
                issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_unknown"))
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

            // Issuer's OIDC context (Max is the Issuer)
            val max = OIDContext(setupWalletWithDid(Max))

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(setupWalletWithDid(Alice))

            // The Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            //
            val metadata = issuerSrv.getIssuerMetadata(max)
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))

            // The Holder sends an Authorization Request to the Authorization Endpoint.
            //
            val authReq = AuthorizationRequestBuilder()
                .withClientId("oid4vci-client")
                .withRedirectUri("urn:ietf:wg:oauth:2.0:oob")
                .buildFrom(credOffer)

            log.info { "AuthorizationRequestUrl: ${authReq.getRequestUrl(metadata)}" }
        }
    }
}