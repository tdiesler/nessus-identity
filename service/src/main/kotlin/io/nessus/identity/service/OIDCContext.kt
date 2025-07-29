package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.OpenIDProviderMetadata
import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import java.time.Instant

open class OIDCContext(ctx: LoginContext) : LoginContext(ctx.getAttachments()) {

    val issuerMetadata get() = assertAttachment(ISSUER_METADATA_ATTACHMENT_KEY)

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
    val authorizationServer get() = (issuerMetadata as? OpenIDProviderMetadata.Draft11)?.authorizationServer
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    init {
        OIDCContextRegistry.put(targetId, this)
    }

    override fun close() {
        OIDCContextRegistry.remove(targetId)
        super.close()
    }

    fun validateAccessToken(bearerToken: SignedJWT) {

        val claims = bearerToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO #235] Properly validate the AccessToken
    }
}

object OIDCContextRegistry {

    private val registry = mutableMapOf<String, OIDCContext>()

    fun assert(dstId: String): OIDCContext {
        return get(dstId) ?: throw IllegalStateException("No OIDCContext for: $dstId")
    }

    fun get(dstId: String): OIDCContext? {
        return registry[dstId]
    }

    fun put(dstId: String, ctx: OIDCContext) {
        registry[dstId] = ctx
    }

    fun remove(dstId: String): OIDCContext? {
        return registry.remove(dstId)
    }
}
