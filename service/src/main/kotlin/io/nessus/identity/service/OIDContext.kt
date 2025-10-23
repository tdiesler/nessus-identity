package io.nessus.identity.service

import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.CREDENTIAL_OFFER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.UserRole

open class OIDContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    var credentialOffer: CredentialOfferDraft11
        get() = assertAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY)
        set(value) = putAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY, value)
    var issuerMetadata: IssuerMetadataDraft11
        get() = assertAttachment(ISSUER_METADATA_ATTACHMENT_KEY)
        set(value) = putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, value)

    // State that is required before access
    //
    val authCode get() = assertAttachment(AUTH_CODE_ATTACHMENT_KEY)
    val accessToken get() = assertAttachment(ACCESS_TOKEN_ATTACHMENT_KEY)
    val authRequest get() = assertAttachment(AUTH_REQUEST_ATTACHMENT_KEY)

    // State that may optionally be provided
    //
    val maybeAuthRequest get() = getAttachment(AUTH_REQUEST_ATTACHMENT_KEY)
    val authRequestCodeVerifier get() = getAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY)

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
