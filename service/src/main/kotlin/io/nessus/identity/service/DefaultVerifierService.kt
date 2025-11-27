package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.DCQLQuery

// DefaultVerifierService ==============================================================================================

class DefaultVerifierService : AbstractVerifierService() {

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

    // Private ---------------------------------------------------------------------------------------------------------
}