package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.IssuerMetadataV10

// AuthorizationContext ===============================================================================================

class AuthorizationContext {

    lateinit var authRequest: AuthorizationRequest
    lateinit var issuerMetadata: IssuerMetadataV10

    var authCode: String? = null
    var codeVerifier: String? = null
    var credOffer: CredentialOfferV10? = null

    val authEndpointUrl get() = issuerMetadata.getAuthorizationAuthEndpoint()

    fun withAuthorizationRequest(authRequest: AuthorizationRequest): AuthorizationContext {
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
        this.issuerMetadata = metadata
        return this
    }
}