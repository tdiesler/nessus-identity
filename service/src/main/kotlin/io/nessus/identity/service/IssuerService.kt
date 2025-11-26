package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService {

    val issuerEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/issuer"
            else -> requireIssuerConfig().baseUrl
        }

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     */
    suspend fun getIssuerMetadata(): IssuerMetadata

    companion object {
        fun createEbsi(): IssuerServiceEbsi32 {
            return IssuerServiceEbsi32();
        }

        fun createKeycloak(): IssuerServiceKeycloak {
            val issuerCfg = requireIssuerConfig()
            return IssuerServiceKeycloak(issuerCfg);
        }
    }
}
