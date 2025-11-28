package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest

// ExperimentalIssuerService ===========================================================================================

interface ExperimentalIssuerService {

    suspend fun createIDTokenRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): AuthorizationRequest

    fun getAuthCodeFromIDToken(
        ctx: LoginContext,
        idTokenJwt: SignedJWT,
    ): String
}