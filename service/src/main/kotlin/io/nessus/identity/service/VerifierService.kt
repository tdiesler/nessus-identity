package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.W3CCredentialV11Jwt

// VerifierService =====================================================================================================

interface VerifierService {

    val verifierEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/verifier"
            else -> requireVerifierConfig().baseUrl
        }

    companion object {
        fun create(): VerifierService {
            return DefaultVerifierService()
        }
    }

    /**
     * Verifier builds the AuthorizationRequest for Verifiable Presentation
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
     */
    suspend fun buildAuthorizationRequestForPresentation(
        clientId: String,
        dcql: DCQLQuery,
        redirectUri: String? = null,
        responseUri: String? = null,
    ): AuthorizationRequest

    fun validateVerifiableCredential(vpcJwt: W3CCredentialV11Jwt, vcp: CredentialParameters? = null)
}
