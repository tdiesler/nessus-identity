package io.nessus.identity.service

import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11

open class OIDContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    // [TODO #281] Derive Issuer metadata from the CredentialOffer
    // https://github.com/tdiesler/nessus-identity/issues/281
    var issuerMetadata: IssuerMetadata
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
    val authorizationServer get() = (issuerMetadata as IssuerMetadataDraft11).authorizationServer
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
