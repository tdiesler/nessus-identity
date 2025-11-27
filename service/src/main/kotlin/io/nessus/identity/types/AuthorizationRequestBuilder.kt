package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import kotlinx.serialization.json.*
import java.security.MessageDigest

class AuthorizationRequestBuilder {

    val log = KotlinLogging.logger {}

    lateinit var clientId: String
    lateinit var codeVerifier: String

    private var clientState: String? = null
    private var codeChallengeMethod: String? = null
    private var credOffer: CredentialOffer? = null
    private var dcqlQuery: DCQLQuery? = null
    private var responseType: String? = null
    private var responseMode: String? = null
    private var redirectUri: String? = null
    private var responseUri: String? = null

    // Internal props
    private var buildAuthorizationDetails = true
    private var explicitIssuerMetadata: IssuerMetadata? = null
    private var scopes = mutableListOf<String>()
    private var credentialConfigurationIds = mutableListOf<String>()
    private var codeChallenge: String? = null

    suspend fun getIssuerMetadata() = requireNotNull(explicitIssuerMetadata
        ?: credOffer?.resolveIssuerMetadata()) { "No issuer metadata"}

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

    fun withCredentialConfigurationIds(configIds: List<String>): AuthorizationRequestBuilder {
        this.credentialConfigurationIds.addAll(configIds)
        return this
    }

    fun withCredentialOffer(credOffer: CredentialOffer): AuthorizationRequestBuilder {
        this.credOffer = credOffer
        return this
    }

    fun withDCQLAssertion(dcql: DCQLQuery): AuthorizationRequestBuilder {
        this.dcqlQuery = dcql
        return this
    }

    fun withIssuerMetadata(metadata: IssuerMetadata): AuthorizationRequestBuilder {
        this.explicitIssuerMetadata = metadata
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

    fun withAuthorizationDetails(flag: Boolean): AuthorizationRequestBuilder {
        this.buildAuthorizationDetails = flag
        return this
    }

    suspend fun build(): AuthorizationRequestV0 {

        require(clientId.isNotBlank()) { "No client_id" }

        if (responseType == null) {
            responseType = "code"
        }

        if (codeChallengeMethod != null) {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val codeVerifierHash = sha256.digest(codeVerifier.toByteArray())
            codeChallenge = Base64URL.encode(codeVerifierHash).toString()
        }

        if (credentialConfigurationIds.isEmpty() && credOffer != null) {
            credentialConfigurationIds.addAll(credOffer!!.credentialConfigurationIds)
        }

        if (responseMode == "direct_post") {
            require(redirectUri == null) { "redirect_uri must be null for direct_post" }
            require(responseUri != null) { "response_uri required for direct_post" }
        }

        val authorizationDetails = mutableListOf<AuthorizationDetail>()
        if (buildAuthorizationDetails) {
            val issuerMetadata = getIssuerMetadata()
            val issuerUri = issuerMetadata.credentialIssuer
            credentialConfigurationIds.forEach {
                authorizationDetails.add(
                    Json.decodeFromString(
                        """{
                            "type": "openid_credential",
                            "credential_configuration_id": "$it",
                            "locations": [ "$issuerUri" ]
                        }"""
                    )
                )
                // [TODO #264] Keycloak requires credential id in scope although already given in authorizationDetails
                // https://github.com/tdiesler/nessus-identity/issues/264
                if (!Features.isProfile(EBSI_V32)) {
                    issuerMetadata as IssuerMetadataV0
                    issuerMetadata.credentialConfigurationsSupported[it]?.scope
                        ?.also { sc -> scopes.add(sc) }
                }
            }
        }

        if (scopes.isEmpty()) {
            scopes.add("openid")
        }

        val authReq = AuthorizationRequestV0(
            clientId = clientId,
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            dcqlQuery = dcqlQuery,
            redirectUri = redirectUri,
            responseMode = responseMode,
            responseType = responseType,
            responseUri = responseUri,
            scope = scopes.joinToString(" "),
            authorizationDetails = authorizationDetails.ifEmpty { null },
            state = clientState,
        )

        return authReq
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}