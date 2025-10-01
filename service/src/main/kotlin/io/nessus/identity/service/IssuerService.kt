package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService<IMType : IssuerMetadata, COType : CredentialOffer> {

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     */
    suspend fun getIssuerMetadata(): IMType

    /**
     * Creates a CredentialOffer for the given subject and credential types
     */
    suspend fun createCredentialOffer(
        ctx: LoginContext,
        subjectId: String,
        types: List<String>,
        userPin: String? = null
    ): COType

    companion object {
        fun createEbsi(): IssuerServiceEbsi32 {
            val ebsi = ConfigProvider.requireEbsiConfig()
            val authUrl = "${ebsi.baseUrl}/auth"
            val issuerUrl = "${ebsi.baseUrl}/issuer"
            return IssuerServiceEbsi32(issuerUrl, authUrl);
        }

        fun createKeycloak(): IssuerServiceKeycloak {
            val issuerCfg = ConfigProvider.requireIssuerConfig()
            return IssuerServiceKeycloak(issuerCfg.baseUrl, issuerCfg.clientId);
        }
    }
}
