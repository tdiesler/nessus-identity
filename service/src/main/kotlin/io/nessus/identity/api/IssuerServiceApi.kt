package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.LoginContext

// IssuerApi ===========================================================================================================

interface IssuerServiceApi {

    suspend fun createCredentialOffer(ctx: LoginContext, sub: String, types: List<String>): CredentialOffer

    suspend fun getCredentialFromRequest(ctx: OIDCContext, accessToken: String, credReq: CredentialRequest) : CredentialResponse

    fun getIssuerMetadataUrl(ctx: LoginContext): String

    fun getIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata

    fun getSupportedCredentials(ctx: LoginContext): Set<CredentialSupported>
}