package io.nessus.identity

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission
import io.nessus.identity.types.AttachmentSupport
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.attachmentKey

// AuthorizationContext ===============================================================================================

class AuthorizationContext(val loginContext: LoginContext) : AttachmentSupport() {

    val authRequest get() = getAttachment(AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
    val codeVerifier get() = getAttachment(CODE_VERIFIER_ATTACHMENT_KEY)
    val credOffer get() = getAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY)
    val issuerMetadata get() = getAttachment(ISSUER_METADATA_ATTACHMENT_KEY)

    val credentialConfigurationIds
        get() = getAttachment(CREDENTIAL_CONFIG_ID_ATTACHMENT_KEY)?.let { listOf(it) }
            ?: credOffer?.credentialConfigurationIds

    companion object {
        val ACCESS_TOKEN_ATTACHMENT_KEY = attachmentKey<SignedJWT>("ACCESS_TOKEN")
        val AUTHORIZATION_CODE_ATTACHMENT_KEY = attachmentKey<String>("AUTHORIZATION_CODE")
        val AUTHORIZATION_REQUEST_ATTACHMENT_KEY = attachmentKey<AuthorizationRequest>()
        val CODE_VERIFIER_ATTACHMENT_KEY = attachmentKey<String>("CODE_VERIFIER")
        val CREDENTIAL_CONFIG_ID_ATTACHMENT_KEY = attachmentKey<String>("CREDENTIAL_CONFIG_ID")
        val CREDENTIAL_OFFER_ATTACHMENT_KEY = attachmentKey<CredentialOffer>()
        val ISSUER_METADATA_ATTACHMENT_KEY = attachmentKey<IssuerMetadata>()

        val EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY = attachmentKey<AuthorizationRequestDraft11>()
        val EBSI32_ISSUER_METADATA_ATTACHMENT_KEY = attachmentKey<IssuerMetadataDraft11>()
        val EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY = attachmentKey<PresentationSubmission>()
        val EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY = attachmentKey<AuthorizationRequestDraft11>("RequestUriObject")
        val USER_PIN_ATTACHMENT_KEY = attachmentKey<String>("USER_PIN")
    }

    suspend fun resolveIssuerMetadata(credentialIssuer: String? = null): IssuerMetadata {
        val issuerMetadata = getAttachment(ISSUER_METADATA_ATTACHMENT_KEY)
            ?: credOffer?.resolveIssuerMetadata()
            ?: credentialIssuer?.run { IssuerMetadata.resolveIssuerMetadata(credentialIssuer) }
        requireNotNull(issuerMetadata) { "No issuer metadata" }
        putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
        return issuerMetadata
    }

    suspend fun assertIssuerMetadata(): IssuerMetadata {
        return issuerMetadata ?: resolveIssuerMetadata()
    }

    suspend fun getAuthorizationMetadata(): AuthorizationMetadata {
        return assertIssuerMetadata().getAuthorizationMetadata()
    }

    fun withAuthorizationRequest(authRequest: AuthorizationRequest): AuthorizationContext {
        putAttachment(AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationContext {
        putAttachment(CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
        return this
    }

    fun withCredentialConfigurationId(configId: String): AuthorizationContext {
        putAttachment(CREDENTIAL_CONFIG_ID_ATTACHMENT_KEY, configId)
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOffer): AuthorizationContext {
        putAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY, credOffer)
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationContext {
        putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, metadata)
        return this
    }
}