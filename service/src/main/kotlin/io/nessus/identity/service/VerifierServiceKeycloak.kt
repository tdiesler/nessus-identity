package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.AuthorizationRequestV10Builder
import io.nessus.identity.types.DCQLQuery

// VerifierService =====================================================================================================

class VerifierServiceKeycloak : AbstractVerifierService() {

    /**
     * Verifier builds the AuthorizationRequest for Verifiable Presentation
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
     */
    fun buildAuthorizationRequestForPresentation(
        clientId: String,
        dcql: DCQLQuery,
        redirectUri: String? = null,
        responseUri: String? = null,
    ): AuthorizationRequestV10 {

        val builder = AuthorizationRequestV10Builder()
            .withResponseType("vp_token")
            .withClientId(clientId)
            .withDCQLAssertion(dcql)

        redirectUri?.also { builder.withRedirectUri(it) }
        responseUri?.also {
            builder.withResponseMode("direct_post")
            builder.withResponseUri(it)
        }

        val authReq = builder.build()
        return authReq
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

}