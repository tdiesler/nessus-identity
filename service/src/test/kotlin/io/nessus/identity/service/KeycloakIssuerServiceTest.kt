package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class KeycloakIssuerServiceTest : AbstractServiceTest() {

    val issuerSrv = IssuerService.createKeycloak() as KeycloakIssuerService

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

            val metadata = issuerSrv.getIssuerMetadata(max) as IssuerMetadataDraft17
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
        }
    }
}