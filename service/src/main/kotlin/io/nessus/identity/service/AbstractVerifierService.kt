package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery

// NativeVerifierService ===============================================================================================

abstract class AbstractVerifierService : VerifierService {

    // VerifierService -------------------------------------------------------------------------------------------------

    // ExperimentalVerifierService -------------------------------------------------------------------------------------

    // LegacyVerifierService -------------------------------------------------------------------------------------------

    override suspend fun buildAuthorizationRequestForPresentation(
        clientId: String,
        dcql: DCQLQuery,
        redirectUri: String?,
        responseUri: String?,
    ): AuthorizationRequestV0 {
        error("Not implemented")
    }
}