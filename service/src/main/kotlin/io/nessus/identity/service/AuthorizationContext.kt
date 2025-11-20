package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.IssuerMetadataV0

// AuthorizationContext ===============================================================================================

class AuthorizationContext(val loginContext: LoginContext? = null) {

    lateinit var authRequest: AuthorizationRequest

    var codeVerifier: String? = null
    var credOffer: CredentialOfferV0? = null

    private var explicitCredentialConfigurationIds: List<String>? = null
    private var explicitIssuerMetadata: IssuerMetadataV0? = null

    suspend fun getIssuerMetadata() = requireNotNull(explicitIssuerMetadata
        ?: credOffer?.resolveIssuerMetadata()) { "No issuer metadata"}

    val credentialConfigurationIds get() =
        explicitCredentialConfigurationIds ?: credOffer?.credentialConfigurationIds

    fun withAuthorizationRequest(authRequest: AuthorizationRequest): AuthorizationContext {
        this.authRequest = authRequest
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationContext {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withCredentialConfigurationId(configId: String): AuthorizationContext {
        explicitCredentialConfigurationIds = listOf(configId)
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOfferV0): AuthorizationContext {
        this.credOffer = credOffer
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadataV0): AuthorizationContext {
        this.explicitIssuerMetadata = metadata
        return this
    }
}