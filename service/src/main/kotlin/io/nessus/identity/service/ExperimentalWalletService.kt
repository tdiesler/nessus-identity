package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.Experimental
import io.nessus.identity.LoginContext
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

// ExperimentalWalletService ===========================================================================================

interface ExperimentalWalletService {

    @Experimental
    suspend fun buildAuthorizationRequestFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequest

    @Experimental
    suspend fun buildCredentialRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): CredentialRequest

    @Experimental
    suspend fun createIDToken(
        ctx: LoginContext, authRequest:
        AuthorizationRequest
    ): SignedJWT

    @Experimental
    suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse

    @Experimental
    suspend fun getTokenRequestFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String
    ): TokenRequest

    @Experimental
    suspend fun sendAuthorizationRequest(
        ctx: LoginContext,
        authEndpointUri: String,
        authRequest: AuthorizationRequest,
    ): String

    @Experimental
    suspend fun sendTokenRequest(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse

}