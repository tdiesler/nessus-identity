package io.nessus.identity.api

import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.service.AuthContext
import io.nessus.identity.service.LoginContext
import kotlinx.serialization.json.JsonObject

// AuthApi =============================================================================================================

interface AuthServiceApi {

    fun getAuthMetadataUrl(ctx: LoginContext): String

    fun getAuthMetadata(ctx: LoginContext): JsonObject

    suspend fun handleAuthorizationRequest(ctx: AuthContext, authReq: AuthorizationRequest): String

    suspend fun handleIDTokenRequest(ctx: AuthContext, queryParams: Map<String, List<String>>): String

    suspend fun handleVPTokenRequest(ctx: AuthContext, queryParams: Map<String, List<String>>): String

    suspend fun sendTokenRequestAuthCode(ctx: AuthContext, authCode: String): TokenResponse

    suspend fun sendTokenRequestPreAuthorized(ctx: AuthContext, grant: GrantDetails): TokenResponse
}