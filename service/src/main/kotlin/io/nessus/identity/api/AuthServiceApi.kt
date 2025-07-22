package io.nessus.identity.api

import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.LoginContext
import kotlinx.serialization.json.JsonObject

// AuthApi =============================================================================================================

interface AuthServiceApi {

    fun getAuthMetadataUrl(ctx: LoginContext): String

    fun getAuthMetadata(ctx: LoginContext): JsonObject

    suspend fun handleAuthorizationRequest(ctx: OIDCContext, authReq: AuthorizationRequest): String

    suspend fun handleIDTokenRequest(ctx: OIDCContext, queryParams: Map<String, List<String>>): String

    suspend fun handleVPTokenRequest(ctx: OIDCContext, queryParams: Map<String, List<String>>): String

    suspend fun sendTokenRequestAuthCode(ctx: OIDCContext, authCode: String): TokenResponse

    suspend fun sendTokenRequestPreAuthorized(ctx: OIDCContext, grant: GrantDetails): TokenResponse
}