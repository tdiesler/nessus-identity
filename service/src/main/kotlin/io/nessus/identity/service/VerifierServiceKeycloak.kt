package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.DCQLQuery

// VerifierService =====================================================================================================

class VerifierServiceKeycloak : AbstractVerifierService() {

    val verifierEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/verifier"
            else -> requireVerifierConfig().baseUrl
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
    ): AuthorizationRequest {

        val builder = AuthorizationRequestBuilder()
            .withResponseType("vp_token")
            .withAuthorizationDetails(false)
            .withClientId(clientId)
            .withDCQLAssertion(dcql)

        redirectUri?.also {
            builder.withRedirectUri(it)
        }
        responseUri?.also {
            builder.withResponseMode("direct_post")
            builder.withResponseUri(it)
        }

        val authReq = builder.build()
        return authReq
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

}