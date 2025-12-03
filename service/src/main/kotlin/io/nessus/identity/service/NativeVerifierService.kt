package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery

// NativeVerifierService ===============================================================================================

class NativeVerifierService: VerifierService {

    /**
     * The endpoint for this service
     */
    override val endpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/verifier"
            else -> requireVerifierConfig().baseUrl
        }

    override val authorizationSvc = NativeAuthorizationService(endpointUri)

    // VerifierService -------------------------------------------------------------------------------------------------

    // ExperimentalVerifierService -------------------------------------------------------------------------------------

    // LegacyVerifierService -------------------------------------------------------------------------------------------

    /**
     * Verifier builds the AuthorizationRequest for Verifiable Presentation
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
     */
    override suspend fun buildAuthorizationRequestForPresentation(
        clientId: String,
        dcql: DCQLQuery,
        redirectUri: String?,
        responseUri: String?,
    ): AuthorizationRequestV0 {

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

    // Private ---------------------------------------------------------------------------------------------------------
}