package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery

// VerifierService =====================================================================================================

interface VerifierService {

    /**
     * The AuthorizationService
     */
    val authorizationSvc: AuthorizationService

    /**
     * The endpoint for this service
     */
    val endpointUri: String

    companion object {
        fun createNative(): VerifierService {
            return NativeVerifierService()
        }
    }

    // ExperimentalVerifierService =====================================================================================

    // LegacyVerifierService ===========================================================================================

    /**
     * Verifier builds the AuthorizationRequest for Verifiable Presentation
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
     */
    suspend fun buildAuthorizationRequestForPresentation(
        clientId: String,
        dcql: DCQLQuery,
        redirectUri: String? = null,
        responseUri: String? = null,
    ): AuthorizationRequestV0
}