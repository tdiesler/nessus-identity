package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class KeycloakIssuerServiceTest : AbstractServiceTest() {

    val issuerSrv = IssuerService.createKeycloak()
    val walletSrv = WalletService.create()

    @Test
    fun testGetIssuerMetadata() {
        /*
            Credential Issuer Metadata
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata

            Issuer Metadata Endpoints
            https://auth.localtest.me/realms/oid4vci/.well-known/openid-configuration
            https://auth.localtest.me/realms/oid4vci/.well-known/openid-credential-issuer
        */
        runBlocking {

            // Issuer's OIDC context (Max is the Issuer)
            val max = login(Max)

            val metadataUrl = issuerSrv.getIssuerMetadataUrl(max)
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSrv.getIssuerMetadata(max)
            metadata.credentialConfigurationsSupported.shouldNotBeNull()
        }
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

            issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_natural_person"))

            assertThrows<IllegalArgumentException> {
                issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_unknown"))
            }
        }
    }

    @Test
    fun testAuthorizationCodeFlow() {
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
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_natural_person"))

            // The Holder sends an Authorization Request to the Authorization Endpoint.
            // The Authorization Endpoint processes the Authorization Request, which typically includes authenticating the End-User and gathering End-User consent.

            val metadata = walletSrv.resolveIssuerMetadata(credOffer.credentialIssuer)
        }
    }
}