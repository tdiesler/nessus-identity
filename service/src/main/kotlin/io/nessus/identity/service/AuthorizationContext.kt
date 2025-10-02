package io.nessus.identity.service

import id.walt.oid4vc.requests.AuthorizationRequest
import io.nessus.identity.extend.getQueryParameters
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadataDraft17
import java.net.URI

// AuthorizationContext ===============================================================================================

class AuthorizationContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    var authCode: String? = null
    var authRequest: AuthorizationRequest? = null
    var codeVerifier: String? = null
    var credOffer: CredentialOfferDraft17? = null
    var metadata: IssuerMetadataDraft17? = null

    val authEndpointUrl get() = metadata!!.getAuthorizationAuthEndpoint()

    val authRequestUrl get() = run {
        val authRequestParams = authRequest!!.getQueryParameters()
        URI("${authEndpointUrl}?$authRequestParams")
    }

    fun withAuthCode(authCode: String): AuthorizationContext {
        this.authCode = authCode
        return this
    }

    fun withAuthorizationRequest(authRequest: AuthorizationRequest): AuthorizationContext {
        this.authRequest = authRequest
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationContext {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOfferDraft17): AuthorizationContext {
        this.credOffer = credOffer
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadataDraft17): AuthorizationContext {
        this.metadata = metadata
        return this
    }
}