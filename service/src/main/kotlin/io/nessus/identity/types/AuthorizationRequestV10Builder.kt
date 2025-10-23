package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.AuthorizationRequestV10.AuthorizationDetail
import kotlinx.serialization.json.*
import java.security.MessageDigest

class AuthorizationRequestV10Builder {

    val log = KotlinLogging.logger {}

    lateinit var clientId: String
    lateinit var redirectUri: String
    lateinit var codeVerifier: String

    private var clientState: String? = null
    private var codeChallengeMethod: String? = null
    private var dcqlQuery: DCQLQuery? = null
    private var metadata: IssuerMetadata? = null
    private var responseType = "code"

    // Internal props
    private val authDetails = mutableListOf<AuthorizationDetail>()
    private var credOffer: CredentialOfferV10? = null
    private var scopes = mutableSetOf("openid")

    var codeChallenge: String? = null

    fun withClientId(clientId: String): AuthorizationRequestV10Builder {
        this.clientId = clientId
        return this
    }

    fun withClientState(clientState: String): AuthorizationRequestV10Builder {
        this.clientState = clientState
        return this
    }

    fun withCodeChallengeMethod(method: String): AuthorizationRequestV10Builder {
        if (method != "S256")
            throw IllegalStateException("Unsupported code challenge method: $method")
        this.codeChallengeMethod = method
        return this
    }

    fun withCodeVerifier(codeVerifier: String): AuthorizationRequestV10Builder {
        this.codeVerifier = codeVerifier
        return this
    }

    fun withDCQLAssertion(dcql: DCQLQuery): AuthorizationRequestV10Builder {
        this.dcqlQuery = dcql
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationRequestV10Builder {
        this.metadata = metadata
        return this
    }

    fun withRedirectUri(redirectUri: String): AuthorizationRequestV10Builder {
        this.redirectUri = redirectUri
        return this
    }

    fun withResponseType(responseType: String): AuthorizationRequestV10Builder {
        this.responseType = responseType
        return this
    }

    suspend fun buildFrom(credOffer: CredentialOfferV10): AuthorizationRequestV10 {
        this.credOffer = credOffer

        if (metadata == null)
            metadata = credOffer.resolveIssuerMetadata()

        credOffer.credentialConfigurationIds.forEach { ctype ->
            authDetails.add(Json.decodeFromString("""{
                        "type": "openid_credential",
                        "credential_configuration_id": "$ctype",
                        "locations": [ "${credOffer.credentialIssuer}" ]
                    }"""))
            // Keycloak requires credential id in scope although already given in authorizationDetails
            // https://github.com/tdiesler/nessus-identity/issues/264
            scopes.add(ctype)
        }
        return buildInternal()
    }

    fun build(): AuthorizationRequestV10 {
        return buildInternal()
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun buildInternal(): AuthorizationRequestV10 {

        if (codeChallengeMethod != null) {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val codeVerifierHash = sha256.digest(codeVerifier.toByteArray())
            codeChallenge = Base64URL.encode(codeVerifierHash).toString()
        }

        val authReq = AuthorizationRequestV10(
            scope = scopes.joinToString(" "),
            clientId = clientId,
            state = clientState,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            dcqlQuery = dcqlQuery,
            authorizationDetails = authDetails.ifEmpty { null },
            redirectUri = redirectUri,
            responseType = responseType,
        )

        log.info { "AuthorizationRequest: ${authReq.toJson()}" }
        return authReq
    }
}