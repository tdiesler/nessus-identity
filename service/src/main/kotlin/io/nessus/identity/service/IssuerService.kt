package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService<IMType: IssuerMetadata, COType: CredentialOffer> {

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
            val issuerUrl = ConfigProvider.issuerEndpointUri
            val authUrl = ConfigProvider.authEndpointUri
            return IssuerServiceEbsi32(issuerUrl, authUrl);
        }
        fun createKeycloak(): IssuerServiceKeycloak {
            // [TODO] Get these value from config
            // https://github.com/tdiesler/nessus-identity/issues/277
            return IssuerServiceKeycloak("https://auth.localtest.me/realms/oid4vci", "oid4vci-client");
        }
    }
}
