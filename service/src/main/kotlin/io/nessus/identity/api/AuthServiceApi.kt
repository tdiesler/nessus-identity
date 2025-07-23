package io.nessus.identity.api

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDCContext
import kotlinx.serialization.json.JsonObject

// AuthApi =============================================================================================================

interface AuthServiceApi {

    fun getAuthMetadataUrl(ctx: LoginContext): String

    fun getAuthMetadata(ctx: LoginContext): JsonObject

    suspend fun validateAuthorizationRequest(ctx: OIDCContext, authReq: AuthorizationRequest)

    suspend fun createIDTokenFromRequest(ctx: OIDCContext, reqParams: Map<String, String>): SignedJWT

    suspend fun handleVPTokenRequest(ctx: OIDCContext, reqParams: Map<String, List<String>>): String

    suspend fun sendTokenRequestAuthCode(ctx: OIDCContext, authCode: String): TokenResponse

    suspend fun sendTokenRequestPreAuthorized(ctx: OIDCContext, grant: GrantDetails): TokenResponse
}