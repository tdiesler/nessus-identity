package io.nessus.identity.api

import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.FlowContext
import io.nessus.identity.service.LoginContext

// IssuerApi ===========================================================================================================

interface IssuerServiceApi {

    fun getIssuerMetadataUrl(ctx: LoginContext): String

    fun getIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata

    suspend fun getCredentialFromRequest(cex: FlowContext, accessToken: String, credReq: CredentialRequest) : CredentialResponse
}