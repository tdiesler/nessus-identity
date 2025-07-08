package io.nessus.identity.api

import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.service.FlowContext
import io.nessus.identity.service.LoginContext
import kotlinx.serialization.json.JsonObject

// AuthApi =============================================================================================================

interface AuthServiceApi {

    fun getAuthMetadataUrl(ctx: LoginContext): String

    fun getAuthMetadata(ctx: LoginContext): JsonObject

    suspend fun handleAuthorizationRequest(cex: FlowContext, authReq: AuthorizationRequest): String

    suspend fun handleIDTokenRequest(cex: FlowContext, queryParams: Map<String, List<String>>): String

    suspend fun handleVPTokenRequest(cex: FlowContext, queryParams: Map<String, List<String>>): String

    suspend fun sendTokenRequestAuthCode(cex: FlowContext, authCode: String): TokenResponse

    suspend fun sendTokenRequestPreAuthorized(cex: FlowContext, grant: GrantDetails): TokenResponse
}