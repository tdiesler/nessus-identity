package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

// ExperimentalWalletService ===========================================================================================

interface ExperimentalWalletService {

    suspend fun buildAuthorizationRequestFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequest

    suspend fun buildCredentialRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): CredentialRequest

    suspend fun getTokenRequestFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String
    ): TokenRequest

    suspend fun createIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): SignedJWT

    suspend fun getAccessTokenFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse

    suspend fun sendAuthorizationRequest(
        ctx: LoginContext,
        authEndpointUri: String,
        authRequest: AuthorizationRequest,
    ): String

    suspend fun sendTokenRequest(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse
}