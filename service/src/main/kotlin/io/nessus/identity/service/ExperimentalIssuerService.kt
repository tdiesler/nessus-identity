package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

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

    suspend fun getTokenResponse(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse
}