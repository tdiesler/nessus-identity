package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest

// ExperimentalAuthorizationService ====================================================================================

interface ExperimentalAuthorizationService {

    suspend fun buildIDTokenRequestJwt(
        ctx: LoginContext,
        targetEndpointUri: String,
        authReq: AuthorizationRequest
    ): SignedJWT

    fun buildIDTokenRequestRedirectUrl(
        authRequest: AuthorizationRequest,
        idTokenRequestJwt: SignedJWT
    ): String

}