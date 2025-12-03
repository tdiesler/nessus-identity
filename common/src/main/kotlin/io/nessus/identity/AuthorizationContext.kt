package io.nessus.identity

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission
import io.nessus.identity.types.AttachmentSupport
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.attachmentKey

// AuthorizationContext ===============================================================================================

// [TODO] Migrate to attachments only

class AuthorizationContext(val loginContext: LoginContext) : AttachmentSupport() {

    lateinit var authRequest: AuthorizationRequestV0

    var codeVerifier: String? = null
    var credOffer: CredentialOffer? = null

    private var explicitCredentialConfigurationIds: List<String>? = null
    private var explicitIssuerMetadata: IssuerMetadata? = null

    val credentialConfigurationIds
        get() =
            explicitCredentialConfigurationIds ?: credOffer?.credentialConfigurationIds

    companion object {
        val ACCESS_TOKEN_ATTACHMENT_KEY = attachmentKey<SignedJWT>("ACCESS_TOKEN")
        val AUTHORIZATION_CODE_ATTACHMENT_KEY = attachmentKey<String>("AUTHORIZATION_CODE")
        val AUTHORIZATION_METADATA_ATTACHMENT_KEY = attachmentKey<AuthorizationMetadata>()
        val CODE_VERIFIER_ATTACHMENT_KEY = attachmentKey<String>("CODE_VERIFIER")
        val ISSUER_METADATA_ATTACHMENT_KEY = attachmentKey<IssuerMetadataV0>()

        val EBSI32_AUTHORIZATION_METADATA_ATTACHMENT_KEY = attachmentKey<AuthorizationMetadata>()
        val EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY = attachmentKey<AuthorizationRequestDraft11>()
        val EBSI32_ISSUER_METADATA_ATTACHMENT_KEY = attachmentKey<IssuerMetadataDraft11>()
        val EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY = attachmentKey<PresentationSubmission>()
        val EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY = attachmentKey<AuthorizationRequestDraft11>("RequestUriObject")
        val USER_PIN_ATTACHMENT_KEY = attachmentKey<String>("USER_PIN")
    }

    suspend fun getIssuerMetadata(): IssuerMetadata {
        return requireNotNull(explicitIssuerMetadata ?: credOffer?.resolveIssuerMetadata())
        { "No credential offer nor explicit issuer metadata" }
    }

    suspend fun getAuthorizationMetadata(): AuthorizationMetadata {
        return getIssuerMetadata().getAuthorizationMetadata()
    }

    fun withAuthorizationRequest(authRequest: AuthorizationRequestV0): AuthorizationContext {
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