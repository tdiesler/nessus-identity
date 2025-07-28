package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.requests.AuthorizationRequest
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.WalletService.log
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.util.Base64
import kotlin.random.Random

class AuthorizationRequestBuilder(val ctx: OIDCContext) {

    private var authorizationDetails: AuthorizationDetails? = null
    private var credentialOffer: CredentialOffer? = null
    private var presentationDefinition: PresentationDefinition? = null

    fun withAuthorizationDetails(authDetails: AuthorizationDetails): AuthorizationRequestBuilder {
        this.authorizationDetails = authDetails
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOffer): AuthorizationRequestBuilder {
        this.credentialOffer = credOffer
        return this
    }

    fun withPresentationDefinition(vpDef: PresentationDefinition): AuthorizationRequestBuilder {
        this.presentationDefinition = vpDef
        return this
    }

    fun build(): AuthorizationRequest {

        // The Holder starts by requesting access for the desired credential from the Issuer's Authorisation Server.
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        val rndBytes = Random.Default.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray())
        val codeChallenge = Base64URL.encode(codeVerifierHash).toString()

        // Build AuthRequestUrl
        //
        val authRedirectUri = "$authEndpointUri/${ctx.targetId}"
        val clientMetadata = OpenIDClientMetadata(
            customParameters = mapOf(
                "authorization_endpoint" to JsonPrimitive(authRedirectUri)
            )
        )

        val issuerState = credentialOffer?.grants[GrantType.authorization_code.value]?.issuerState

        val authRequest = AuthorizationRequest(
            scope = setOf("openid"),
            clientId = ctx.did,
            state = ctx.walletId,
            clientMetadata = clientMetadata,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            authorizationDetails = authorizationDetails?.let { listOf(it) },
            presentationDefinition = presentationDefinition,
            redirectUri = authRedirectUri,
            issuerState = issuerState
        )

        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        ctx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
        log.info { "AuthorizationRequest: ${Json.encodeToString(authRequest)}" }

        return authRequest
    }
}