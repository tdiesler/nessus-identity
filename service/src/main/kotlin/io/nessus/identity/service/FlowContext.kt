package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.CredentialResponse
import java.time.Instant
import kotlin.collections.set

class FlowContext(ctx: LoginContext) : LoginContext(ctx.authToken, ctx.walletInfo, ctx.didInfo) {

    // State that is required before access
    //
    lateinit var issuerMetadata: OpenIDProviderMetadata

    lateinit var authCode: String
    lateinit var accessToken: SignedJWT

    lateinit var credentialOffer: CredentialOffer
    lateinit var offeredCredential: OfferedCredential

    lateinit var credResponse: CredentialResponse

    // State that may optionally be provided
    //
    var maybeAuthRequest: AuthorizationRequest? = null
    var authRequestCodeVerifier: String? = null

    var authRequest: AuthorizationRequest
        get() = maybeAuthRequest ?: throw IllegalStateException("No AuthorizationRequest")
        set(ar) { maybeAuthRequest = ar }

    val authorizationEndpoint
        get() = (issuerMetadata as? OpenIDProviderMetadata.Draft11)?.authorizationServer
            ?: (issuerMetadata as? OpenIDProviderMetadata.Draft13)?.authorizationEndpoint
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    val extras = mutableMapOf<String, Any>()

    init {
        registry[subjectId] = this
    }

    companion object {

        // A global registry that allows us to resolve a CredentialExchange from subjectId
        private val registry = mutableMapOf<String, FlowContext>()

        fun resolveCredentialExchange(subId: String): FlowContext? {
            return registry[subId]
        }

        fun requireCredentialExchange(subId: String): FlowContext {
            return resolveCredentialExchange(subId)
                ?: throw IllegalStateException("Cannot resolve CredentialExchange for: $subId")
        }
    }

    override fun close() {
        registry.remove(subjectId)
        super.close()
    }

    fun getRequestObject(key: String): Any? {
        return extras[key]
    }

    fun putRequestObject(key: String, obj: Any) {
        extras[key] = obj
    }

    fun validateBearerToken(bearerToken: SignedJWT) {

        val claims = bearerToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO] consider other access token checks
    }
}