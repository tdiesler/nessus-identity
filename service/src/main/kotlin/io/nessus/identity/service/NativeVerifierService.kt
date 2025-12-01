package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery

// NativeVerifierService ==============================================================================================

class NativeVerifierService : AbstractVerifierService(), VerifierService {

    override val authorizationSvc = AuthorizationService.create()

    // ExperimentalVerifierService -------------------------------------------------------------------------------------

    // VerifierService -------------------------------------------------------------------------------------------------

    /**
     * Get the authorization metadata
     */
    override fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata {
        val targetUri = "$endpointUri/${ctx.targetId}"
        return authorizationSvc.buildAuthorizationMetadata(targetUri)
    }

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