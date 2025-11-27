package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationMetadata

// VerifierService =====================================================================================================

interface VerifierService: ExperimentalVerifierService, LegacyVerifierService {

    /**
     * The AuthorizationService
     */
    val authorizationSvc: AuthorizationService

    /**
     * The endpoint for this service
     */
    val endpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/verifier"
            else -> requireVerifierConfig().baseUrl
        }

    /**
     * Get the authorization metadata
     */
    fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata

    companion object {
        fun create(): VerifierService {
            return NativeVerifierService()
        }
    }

}
