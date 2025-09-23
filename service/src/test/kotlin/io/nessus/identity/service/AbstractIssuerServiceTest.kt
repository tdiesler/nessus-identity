package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test


abstract class AbstractIssuerServiceTest<IMDType: IssuerMetadata> : AbstractServiceTest() {

    val walletSvc = WalletService.create()
    lateinit var issuerSvc: IssuerService<IMDType>

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

            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }
}