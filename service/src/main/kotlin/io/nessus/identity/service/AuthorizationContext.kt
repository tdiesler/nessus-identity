package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.IssuerMetadataV10
import java.net.URI

// AuthorizationContext ===============================================================================================

class AuthorizationContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    lateinit var authRequest: AuthorizationRequestV10
    lateinit var metadata: IssuerMetadataV10

    var authCode: String? = null
    var codeVerifier: String? = null
    var credOffer: CredentialOfferV10? = null

    val authEndpointUrl get() = metadata.getAuthorizationAuthEndpoint()

    val authRequestUrl get() = run {
        val authRequestParams = authRequest.toHttpParameters()
        URI("${authEndpointUrl}?$authRequestParams")
    }

    fun withAuthCode(authCode: String): AuthorizationContext {
        this.authCode = authCode
        return this
    }

    fun withAuthorizationRequest(authRequest: AuthorizationRequestV10): AuthorizationContext {
        this.authRequest = authRequest
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationContext {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOfferV10): AuthorizationContext {
        this.credOffer = credOffer
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadataV10): AuthorizationContext {
        this.metadata = metadata
        return this
    }
}