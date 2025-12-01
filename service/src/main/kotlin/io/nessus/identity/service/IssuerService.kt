package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.config.User
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService: UserAccessService, ExperimentalIssuerService, LegacyIssuerService {

    /**
     * The AuthorizationService
     */
    val authorizationSvc: AuthorizationService

    /**
     * The endpoint for this service
     */
    val endpointUri
        get() = when(this) {
            is IssuerServiceEbsi32 -> "${requireEbsiConfig().baseUrl}/issuer"
            else -> requireIssuerConfig().baseUrl
        }

    companion object {

        const val KNOWN_ISSUER_EBSI_V3 = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"

        fun create(): IssuerService {
            return when(Features.getProfile()) {
                EBSI_V32 -> createEbsi()
                else -> createKeycloak()
            }
        }
        fun createEbsi(): IssuerService {
            val issuerCfg = requireIssuerConfig()
            return IssuerServiceEbsi32(issuerCfg);
        }
        fun createKeycloak(): IssuerService {
            val issuerCfg = requireIssuerConfig()
            return IssuerServiceKeycloak(issuerCfg);
        }
    }

    /**
     * Get the Issuer's authorization metadata
     */
    suspend fun getAuthorizationMetadata(): AuthorizationMetadata

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     */
    suspend fun getIssuerMetadata(): IssuerMetadata

    /**
     * Creates a CredentialOffer for the given credential configuration id
     */
    suspend fun createCredentialOffer(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): CredentialOffer

    /**
     * Creates a CredentialOfferUri for the given credential configuration id
     */
    suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): String
}
