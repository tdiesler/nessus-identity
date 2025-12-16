package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.Experimental
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.CredentialResponse
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse

// ExperimentalIssuerService ===========================================================================================

interface ExperimentalIssuerService {


    @Experimental
    suspend fun createIDTokenRequest(
        authRequest: AuthorizationRequest
    ): AuthorizationRequest

    @Experimental
    fun getAuthCodeFromIDToken(
        idTokenJwt: SignedJWT,
    ): String

    @Experimental
    suspend fun getCredentialFromAcceptanceToken(
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse

    @Experimental
    suspend fun getCredentialFromRequest(
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false
    ): CredentialResponse

    @Experimental
    suspend fun getTokenResponse(
        tokenRequest: TokenRequest
    ): TokenResponse

}