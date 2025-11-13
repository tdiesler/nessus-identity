package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.*
import java.security.MessageDigest

class AuthorizationRequestBuilder {

    val log = KotlinLogging.logger {}

    lateinit var clientId: String
    lateinit var codeVerifier: String

    private var clientState: String? = null
    private var codeChallengeMethod: String? = null
    private var dcqlQuery: DCQLQuery? = null
    private var metadata: IssuerMetadata? = null
    private var responseType: String? = null
    private var responseMode: String? = null
    private var redirectUri: String? = null
    private var responseUri: String? = null

    // Internal props
    private val authDetails = mutableListOf<AuthorizationDetails>()
    private var credOffer: CredentialOfferV10? = null
    private var scopes = mutableListOf<String>()

    var codeChallenge: String? = null

    fun withClientId(clientId: String): AuthorizationRequestBuilder {
        this.clientId = clientId
        return this
    }

    fun withClientState(clientState: String): AuthorizationRequestBuilder {
        this.clientState = clientState
        return this
    }

    fun withCodeChallengeMethod(method: String): AuthorizationRequestBuilder {
        require(method == "S256") { "Unsupported code challenge method: $method" }
        this.codeChallengeMethod = method
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationRequestBuilder {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withDCQLAssertion(dcql: DCQLQuery): AuthorizationRequestBuilder {
        this.dcqlQuery = dcql
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationRequestBuilder {
        this.metadata = metadata
        return this
    }

    fun withRedirectUri(redirectUri: String): AuthorizationRequestBuilder {
        this.redirectUri = redirectUri
        return this
    }

    fun withResponseType(responseType: String): AuthorizationRequestBuilder {
        this.responseType = responseType
        return this
    }

    fun withResponseMode(responseMode: String): AuthorizationRequestBuilder {
        this.responseMode = responseMode
        return this
    }

    fun withResponseUri(responseUri: String): AuthorizationRequestBuilder {
        this.responseUri = responseUri
        return this
    }

    fun withScopes(scopes: List<String>): AuthorizationRequestBuilder {
        this.scopes.addAll(scopes)
        return this
    }

    fun withAuthorizationDetails(): AuthorizationRequestBuilder {
        val issuerUri = metadata?.credentialIssuer ?: error("No issuer metadata")
        addAuthorizationDetails(issuerUri, scopes)
        return this
    }

    fun buildFrom(credOffer: CredentialOfferV10): AuthorizationRequest {
        this.credOffer = credOffer

        val issuerUri = credOffer.credentialIssuer
        addAuthorizationDetails(issuerUri, credOffer.credentialConfigurationIds)

        return buildInternal()
    }

    fun build(): AuthorizationRequest {
        return buildInternal()
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    fun addAuthorizationDetails(issuerUri: String, ctypes: List<String>) {
        ctypes.forEach {
            authDetails.add(
                Json.decodeFromString(
                    """{
                            "type": "openid_credential",
                            "credential_configuration_id": "$it",
                            "locations": [ "$issuerUri" ]
                        }"""
                )
            )
        }
        // [TODO #264] Keycloak requires credential id in scope although already given in authorizationDetails
        // https://github.com/tdiesler/nessus-identity/issues/264
        if (scopes.isEmpty()) {
            scopes.addAll(ctypes)
        }
    }

    private fun buildInternal(): AuthorizationRequest {

        require(clientId.isNotBlank()) { "No client_id" }
        if (responseType == null) {
            responseType = "code"
        }

        if (codeChallengeMethod != null) {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val codeVerifierHash = sha256.digest(codeVerifier.toByteArray())
            codeChallenge = Base64URL.encode(codeVerifierHash).toString()
        }

        if (responseMode == "direct_post") {
            require(redirectUri == null) { "redirect_uri must be null for direct_post" }
            require(responseUri != null) { "response_uri required for direct_post" }
        }

        val authReq = AuthorizationRequest(
            authorizationDetails = authDetails.ifEmpty { null },
            clientId = clientId,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            dcqlQuery = dcqlQuery,
            redirectUri = redirectUri,
            responseMode = responseMode,
            responseType = responseType,
            responseUri = responseUri,
            scope = scopes.joinToString(" "),
            state = clientState,
        )

        return authReq
    }
}