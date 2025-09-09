package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class DefaultIssuerServiceTest : AbstractServiceTest() {

    val issuerSrv = IssuerService.create() as DefaultIssuerService

    @Test
    fun issuerMetadata() {
        runBlocking {
            val max = loginWithWallet(Max)

            val metadataUrl = issuerSrv.getIssuerMetadataUrl(max)
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSrv.getIssuerMetadata(max) as IssuerMetadataDraft11
            metadata.credentialsSupported.shouldNotBeNull()
        }
    }
}