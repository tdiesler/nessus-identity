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
    suspend fun createCredentialOffer(subId: String, types: List<String>, userPin: String? = null): COType

    companion object {
        /**
         * Creates the default IssuerService
         */
        fun createEbsi(ctx: OIDContext): IssuerServiceEbsi32 {
            val issuerUrl = ConfigProvider.issuerEndpointUri
            val authUrl = ConfigProvider.authEndpointUri
            return IssuerServiceEbsi32(ctx, issuerUrl, authUrl);
        }
        /**
         * Creates the Keycloak IssuerService
         */
        fun create(ctx: OIDContext): IssuerServiceDraft17 {
            return IssuerServiceDraft17(ctx, "https://auth.localtest.me/realms/oid4vci");
        }
    }
}
