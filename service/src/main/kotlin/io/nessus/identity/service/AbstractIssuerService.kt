package io.nessus.identity.service

import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<COType: CredentialOffer, IMDType: IssuerMetadata>(val issuerUrl: String) : IssuerService<COType, IMDType> {

    protected var issuerMetadata : IMDType? = null

    override fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }

    final override suspend fun getIssuerMetadata(ctx: LoginContext): IMDType {
        if (issuerMetadata == null) {
            issuerMetadata = getIssuerMetadataInternal(ctx)
        }
        return issuerMetadata!!
    }

    protected abstract suspend fun getIssuerMetadataInternal(ctx: LoginContext): IMDType
}