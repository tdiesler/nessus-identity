package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.requests.AuthorizationRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.*
import java.security.MessageDigest

class AuthorizationRequestDraft11Builder {

    val log = KotlinLogging.logger {}

    lateinit var clientId: String
    lateinit var redirectUri: String
    lateinit var codeVerifier: String

    private var clientState: String? = null
    private var codeChallengeMethod: String? = null
    private var metadata: IssuerMetadata? = null
    private var presentationDefinition: PresentationDefinition? = null

    // Internal props
    private val authDetails = mutableListOf<AuthorizationDetails>()
    private var credOffer: CredentialOffer? = null
    private var scopes = mutableSetOf("openid")

    var codeChallenge: String? = null

    fun withClientId(id: String): AuthorizationRequestDraft11Builder {
        this.clientId = id
        return this
    }

    fun withClientState(state: String): AuthorizationRequestDraft11Builder {
        this.clientState = state
        return this
    }

    fun withCodeChallengeMethod(method: String): AuthorizationRequestDraft11Builder {
        if (method != "S256")
            throw IllegalStateException("Unsupported code challenge method: $method")
        this.codeChallengeMethod = method
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationRequestDraft11Builder {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationRequestDraft11Builder {
        this.metadata = metadata
        return this
    }

    fun withPresentationDefinition(vpDef: PresentationDefinition): AuthorizationRequestDraft11Builder {
        this.presentationDefinition = vpDef
        return this
    }

    fun withRedirectUri(uri: String): AuthorizationRequestDraft11Builder {
        this.redirectUri = uri
        return this
    }

    suspend fun buildFrom(credOffer: CredentialOffer): AuthorizationRequest {
        this.credOffer = credOffer

        if (metadata == null)
            metadata = credOffer.resolveIssuerMetadata()

        when (credOffer) {

            is CredentialOfferDraft11 -> {
                val waltIdOffer = credOffer.toWaltIdCredentialOffer()
                val waltIdMetadata = (metadata as IssuerMetadataDraft11).toWaltIdIssuerMetadata()
                val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(waltIdOffer, waltIdMetadata)

                log.info { "Offered Credentials: ${Json.encodeToString(offeredCredentials)}" }
                if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
                val offeredCred = offeredCredentials.first()

                authDetails.add(AuthorizationDetails.fromOfferedCredential(offeredCred, credOffer.credentialIssuer))
            }

            is CredentialOfferV10 -> {
                credOffer.credentialConfigurationIds.forEach { ctype ->
                    authDetails.add(AuthorizationDetails.fromJSONString("""{
                        "type": "openid_credential",
                        "credential_configuration_id": "$ctype",
                        "locations": [ "${credOffer.credentialIssuer}" ]
                    }"""))
                    // Keycloak requires credential id in scope although already given in authorizationDetails
                    // https://github.com/tdiesler/nessus-identity/issues/264
                    scopes.add(ctype)
                }
            }
        }
        return buildInternal()
    }

    fun build(): AuthorizationRequest {
        return buildInternal()
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun buildInternal(): AuthorizationRequest {

        // The Holder starts by requesting access for the desired credential from the Issuer's Authorisation Server.
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        if (codeChallengeMethod != null) {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val codeVerifierHash = sha256.digest(codeVerifier.toByteArray())
            codeChallenge = Base64URL.encode(codeVerifierHash).toString()
        }

        // Build AuthRequestUrl
        //
        val clientMetadata = OpenIDClientMetadata(
            customParameters = mapOf(
                "authorization_endpoint" to JsonPrimitive(redirectUri)
            )
        )

        val issuerState = credOffer?.getAuthorizationCodeGrant()?.issuerState

        val authRequest = AuthorizationRequest(
            scope = scopes,
            clientId = clientId,
            state = clientState,
            clientMetadata = clientMetadata,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            authorizationDetails = authDetails,
            presentationDefinition = presentationDefinition,
            redirectUri = redirectUri,
            issuerState = issuerState
        )

        log.info { "AuthorizationRequest: ${Json.encodeToString(authRequest)}" }
        return authRequest
    }
}