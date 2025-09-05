package io.nessus.identity.service

abstract class AbstractIssuerService(val issuerUrl: String) : IssuerService {

    override fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return metadataUrl
    }
}