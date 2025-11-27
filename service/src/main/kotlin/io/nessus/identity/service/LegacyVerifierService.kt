package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.W3CCredentialV11Jwt

// LegacyVerifierService ===============================================================================================

interface LegacyVerifierService {

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

    fun validateVerifiableCredential(vpcJwt: W3CCredentialV11Jwt, vcp: CredentialParameters? = null)

}