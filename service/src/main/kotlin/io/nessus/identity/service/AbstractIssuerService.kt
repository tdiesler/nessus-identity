package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<IMDType : IssuerMetadata>(val ctx: OIDContext, val issuerUrl: String) : IssuerService<IMDType> {

    val log = KotlinLogging.logger {}

    protected var metadata: IMDType? = null

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }

    final override suspend fun getIssuerMetadata(): IMDType {
        if (metadata == null) {
            metadata = getIssuerMetadataInternal(ctx)
            ctx?.also {
                ctx.issuerMetadata = (metadata as IssuerMetadata)
            }
        }
        return metadata!!
    }

    protected abstract suspend fun getIssuerMetadataInternal(ctx: OIDContext?): IMDType
}