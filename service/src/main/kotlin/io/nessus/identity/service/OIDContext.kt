package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.IssuerMetadataDraft11

open class OIDContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    var credentialOffer: CredentialOfferDraft11
        get() = assertAttachment(EBSI32_CREDENTIAL_OFFER_ATTACHMENT_KEY)
        set(value) = putAttachment(EBSI32_CREDENTIAL_OFFER_ATTACHMENT_KEY, value)
    var issuerMetadata: IssuerMetadataDraft11
        get() = assertAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY)
        set(value) = putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, value)

    // State that is required before access
    //
    val authCode get() = assertAttachment(EBSI32_AUTH_CODE_ATTACHMENT_KEY)
    val accessToken get() = assertAttachment(EBSI32_ACCESS_TOKEN_ATTACHMENT_KEY)
    val authRequest get() = assertAttachment(EBSI32_AUTH_REQUEST_ATTACHMENT_KEY)

    // State that may optionally be provided
    //
    val maybeAuthRequest get() = getAttachment(EBSI32_AUTH_REQUEST_ATTACHMENT_KEY)
    val authRequestCodeVerifier get() = getAttachment(EBSI32_AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY)

    // Derived State from other properties
    //
    val authorizationServer get() = (issuerMetadata).authorizationServer
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    init {
        OIDCContextRegistry.put(targetId, this)
    }

    override fun close() {
        OIDCContextRegistry.remove(targetId)
        super.close()
    }

    companion object {
        val EBSI32_ACCESS_TOKEN_ATTACHMENT_KEY = attachmentKey<SignedJWT>("ACCESS_TOKEN")
        val EBSI32_AUTH_CODE_ATTACHMENT_KEY = attachmentKey<String>("AUTH_CODE")
        val EBSI32_AUTH_REQUEST_ATTACHMENT_KEY = attachmentKey<AuthorizationRequestDraft11>()
        val EBSI32_AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY = attachmentKey<String>("AUTH_CODE_VERIFIER")
        val EBSI32_CREDENTIAL_OFFER_ATTACHMENT_KEY = attachmentKey<CredentialOfferDraft11>()
        val EBSI32_ISSUER_METADATA_ATTACHMENT_KEY = attachmentKey<IssuerMetadataDraft11>()
        val EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY = attachmentKey<PresentationSubmission>()
        val EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY = attachmentKey<Any>("RequestUriObject")
    }
}

object OIDCContextRegistry {

    private val registry = mutableMapOf<String, OIDContext>()

    fun assert(dstId: String): OIDContext {
        return get(dstId) ?: throw IllegalStateException("No OIDCContext for: $dstId")
    }

    fun get(dstId: String): OIDContext? {
        return registry[dstId]
    }

    fun put(dstId: String, ctx: OIDContext) {
        registry[dstId] = ctx
    }

    fun remove(dstId: String): OIDContext? {
        return registry.remove(dstId)
    }
}
