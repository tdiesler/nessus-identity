package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test


abstract class AbstractIssuerServiceTest<COType: CredentialOffer, IMDType: IssuerMetadata> : AbstractServiceTest() {

    val walletSrv = WalletService.create()
    lateinit var issuerSrv: IssuerService<COType, IMDType>

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
            val max = OIDContext(setupWalletWithDid(Max))

            val metadataUrl = issuerSrv.getIssuerMetadataUrl(max)
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSrv.getIssuerMetadata(max)
            metadata.shouldNotBeNull()
        }
    }
}