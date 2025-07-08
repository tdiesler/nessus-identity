package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.responses.TokenResponse
import io.nessus.identity.service.FlowContext

// AuthApi =============================================================================================================

interface AuthApi {

    suspend fun sendTokenRequestAuthCode(cex: FlowContext, authCode: String): TokenResponse

    suspend fun sendTokenRequestPreAuthorized(cex: FlowContext, grant: GrantDetails): TokenResponse
}