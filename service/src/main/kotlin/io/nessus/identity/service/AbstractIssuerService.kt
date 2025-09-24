package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<IMType: IssuerMetadata, COType: CredentialOffer>(
    val ctx: OIDContext,
    val issuerUrl: String,
) : IssuerService<IMType, COType> {

    val log = KotlinLogging.logger {}

    protected var metadata: IMType? = null

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }

    @Suppress("UNCHECKED_CAST")
    final override suspend fun getIssuerMetadata(): IMType {
        if (metadata == null) {
            metadata = getIssuerMetadataInternal()
            ctx.issuerMetadata = (metadata as IssuerMetadata)
        }
        return metadata as IMType
    }

    protected abstract suspend fun getIssuerMetadataInternal(): IMType
}