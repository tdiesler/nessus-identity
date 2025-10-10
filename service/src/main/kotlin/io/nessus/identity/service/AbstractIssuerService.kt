package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<IMType: IssuerMetadata, COType: CredentialOffer>(
    val issuerUrl: String,
) : IssuerService<IMType, COType> {

    val log = KotlinLogging.logger {}

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }
}