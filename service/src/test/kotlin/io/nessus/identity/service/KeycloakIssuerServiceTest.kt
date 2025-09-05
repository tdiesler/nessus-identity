package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class KeycloakIssuerServiceTest : AbstractServiceTest() {

    val issuer = IssuerService.createKeycloak() as KeycloakIssuerService

    @Test
    fun issuerMetadata() {
        runBlocking {
            val ctx = login(Max)

            val metadataUrl = issuer.getIssuerMetadataUrl(ctx)
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuer.getIssuerMetadata(ctx) as IssuerMetadataDraft17
            metadata.credentialConfigurationsSupported.shouldNotBeNull()
        }
    }
}