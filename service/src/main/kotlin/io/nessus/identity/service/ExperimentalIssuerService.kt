package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.CredentialResponse
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

    suspend fun getNativeCredentialFromRequest(
        ctx: LoginContext,
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false
    ): CredentialResponse

    suspend fun getNativeCredentialFromAcceptanceToken(
        ctx: LoginContext,
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse
}