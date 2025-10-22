package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.AuthorizationRequestV10Builder
import io.nessus.identity.types.DCQLQuery

// VerifierService =====================================================================================================

class VerifierServiceKeycloak : AbstractVerifierService() {

    /**
     * Verifier builds the AuthorizationRequest from an AuthorizationRequest
     */
    fun authContextForPresentation(
        clientId: String,
        redirectUri: String,
        dcql: DCQLQuery,
    ): AuthorizationContext {

        val authReq = buildAuthorizationRequest(clientId, redirectUri, dcql)

        val authContext = AuthorizationContext()
            .withAuthorizationRequest(authReq)

        return authContext
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun buildAuthorizationRequest(
        clientId: String,
        redirectUri: String,
        dcql: DCQLQuery,
    ): AuthorizationRequestV10 {

        val builder = AuthorizationRequestV10Builder()
            .withClientId(clientId)
            .withDCQLAssertion(dcql)
            .withRedirectUri(redirectUri)
            .withResponseType("vp_token")

        val authReq = builder.build()
        return authReq
    }
}