package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

// ExperimentalAuthorizationService ====================================================================================

interface ExperimentalAuthorizationService {

    suspend fun createIDTokenRequestJwt(
        ctx: LoginContext,
        targetEndpointUri: String,
        authReq: AuthorizationRequest
    ): SignedJWT

    fun buildIDTokenAuthorizationRequest(
        redirectUri: String,
        idTokenRequestJwt: SignedJWT
    ): AuthorizationRequest

    suspend fun createIDTokenJwt(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenRequestJwt: SignedJWT
    ): SignedJWT

    suspend fun sendIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenJwt: SignedJWT
    ): String

    fun getIDTokenRedirectUrl(
        ctx: LoginContext,
        idTokenJwt: SignedJWT
    ): String

    suspend fun getTokenResponse(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse

    fun validateAccessToken(accessToken: SignedJWT)
}