package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.TokenResponse

// LegacyWalletService =================================================================================================

interface LegacyWalletService {

    // [TODO] Get default client_id from config
    val defaultClientId: String

    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequestV0

    suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
    ): SubmissionBundle

    suspend fun getAuthorizationCode(
        ctx: LoginContext,
        clientId: String = defaultClientId,
        username: String,
        password: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): String

    suspend fun getAccessTokenFromDirectAccess(
        ctx: LoginContext,
        clientId: String = defaultClientId,
    ): TokenResponse

    suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: io.nessus.identity.types.AuthorizationRequestV0): TokenResponse
}