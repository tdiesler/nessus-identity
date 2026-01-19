package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.LoginContext
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

interface AuthorizationService {

    /**
     * The endpoint uri for this service
     */
    val endpointUri: String

    /**
     * The Wallet authorization callback Uri
     */
    val authorizationCallbackUri
        get() = "$endpointUri/auth/callback"

    fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata

    fun getAuthorizationMetadataUrl(ctx: LoginContext): String

    suspend fun createIDToken(
        ctx: LoginContext,
        idTokenRequest: AuthorizationRequest
    ): SignedJWT

    fun createIDTokenAuthorizationRequest(
        redirectUri: String,
        idTokenRequestJwt: SignedJWT
    ): AuthorizationRequest

    suspend fun createIDTokenJwt(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenRequestJwt: SignedJWT
    ): SignedJWT

    suspend fun createIDTokenRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): AuthorizationRequest

    suspend fun createIDTokenRequestJwt(
        ctx: LoginContext,
        targetEndpointUri: String,
        authReq: AuthorizationRequest
    ): SignedJWT

    fun getIDTokenRedirectUrl(
        ctx: LoginContext,
        idTokenJwt: SignedJWT
    ): String

    suspend fun getTokenResponse(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse

    suspend fun sendIDToken(
        ctx: LoginContext,
        idTokenRequest: AuthorizationRequest,
        idTokenJwt: SignedJWT
    ): String

    fun validateAccessToken(accessToken: SignedJWT)
}