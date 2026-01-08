package io.nessus.identity.service

import io.nessus.identity.config.VerifierConfig
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.AuthorizationRequestV0Builder
import io.nessus.identity.types.DCQLQuery

// NativeVerifierService ===============================================================================================

class NativeVerifierService(val config: VerifierConfig) : AbstractVerifierService() {

    /**
     * The endpoint for this service
     */
    override val endpointUri = config.baseUrl
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

        val builder = AuthorizationRequestV0Builder()
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