package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata

// AuthorizationContext ===============================================================================================

class AuthorizationContext(val loginContext: LoginContext? = null): AttachmentSupport() {

    lateinit var authRequest: AuthorizationRequest

    var codeVerifier: String? = null
    var credOffer: CredentialOffer? = null

    private var explicitCredentialConfigurationIds: List<String>? = null
    private var explicitIssuerMetadata: IssuerMetadata? = null

    val credentialConfigurationIds get() =
        explicitCredentialConfigurationIds ?: credOffer?.credentialConfigurationIds

    val filteredConfigurationIds
        get() = credentialConfigurationIds?.filter { it !in listOf("VerifiableAttestation", "VerifiableCredential")  }

    companion object {
        val EBSI32_AUTH_CODE_ATTACHMENT_KEY = attachmentKey<String>("AUTH_CODE")
        val EBSI32_AUTH_REQUEST_ATTACHMENT_KEY = attachmentKey<id.walt.oid4vc.requests.AuthorizationRequest>()
        val EBSI32_CODE_VERIFIER_ATTACHMENT_KEY = attachmentKey<String>("CODE_VERIFIER")
        val EBSI32_USER_PIN_ATTACHMENT_KEY = attachmentKey<String>("USER_PIN")
    }

    suspend fun getIssuerMetadata(): IssuerMetadata {
        return requireNotNull(explicitIssuerMetadata ?: credOffer?.resolveIssuerMetadata())
        { "No credential offer nor explicit issuer metadata" }
    }

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

    fun withCredentialOffer(credOffer: CredentialOffer): AuthorizationContext {
        this.credOffer = credOffer
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationContext {
        this.explicitIssuerMetadata = metadata
        return this
    }
}