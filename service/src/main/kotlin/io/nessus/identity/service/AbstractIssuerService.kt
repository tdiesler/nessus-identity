package io.nessus.identity.service

import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<COType: CredentialOffer, IMDType: IssuerMetadata>(val issuerUrl: String) : IssuerService<COType, IMDType> {

    protected var metadata : IMDType? = null

    override fun getIssuerMetadataUrl(ctx: OIDContext): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }

    final override suspend fun getIssuerMetadata(ctx: OIDContext): IMDType {
        if (metadata == null) {
            metadata = getIssuerMetadataInternal(ctx)
            ctx.issuerMetadata = (metadata as IssuerMetadata)
        }
        return metadata!!
    }

    protected abstract suspend fun getIssuerMetadataInternal(ctx: OIDContext): IMDType
}