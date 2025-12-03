package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.Experimental
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

    @Experimental
    suspend fun createIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): SignedJWT

    @Experimental
    fun createIDTokenAuthorizationRequest(
        redirectUri: String,
        idTokenRequestJwt: SignedJWT
    ): AuthorizationRequest

    @Experimental
    suspend fun createIDTokenJwt(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenRequestJwt: SignedJWT
    ): SignedJWT

    @Experimental
    suspend fun createIDTokenRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): AuthorizationRequest

    @Experimental
    suspend fun createIDTokenRequestJwt(
        ctx: LoginContext,
        targetEndpointUri: String,
        authReq: AuthorizationRequest
    ): SignedJWT

    @Experimental
    fun getIDTokenRedirectUrl(
        ctx: LoginContext,
        idTokenJwt: SignedJWT
    ): String

    @Experimental
    suspend fun getTokenResponse(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse

    @Experimental
    suspend fun sendIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenJwt: SignedJWT
    ): String

    @Experimental
    fun validateAccessToken(accessToken: SignedJWT)
}