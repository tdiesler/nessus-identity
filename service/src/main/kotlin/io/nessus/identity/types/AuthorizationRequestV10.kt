package io.nessus.identity.types

import com.nimbusds.jose.util.Base64URL
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.AuthorizationRequestV10.AuthorizationDetail
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

@Serializable
data class AuthorizationRequestV10(

    @SerialName("client_id")
    val clientId: String,

    @SerialName("redirect_uri")
    val redirectUri: String?,

    @SerialName("response_type")
    val responseType: String,

    @SerialName("response_mode")
    val responseMode: String?,

    @SerialName("response_uri")
    val responseUri: String?,

    @SerialName("nonce")
    val nonce: String? = null,

    @SerialName("scope")
    val scope: String? = null,

    @SerialName("state")
    val state: String? = null,

    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetail>? = null,

    @SerialName("code_challenge")
    val codeChallenge: String? = null,

    @SerialName("code_challenge_method")
    val codeChallengeMethod: String? = null,

    // Request Parameters defined in "OpenID for Verifiable Presentations 1.0"
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters

    @SerialName("client_metadata")
    val clientMetadata: ClientMetadata? = null,

    @SerialName("dcql_query")
    val dcqlQuery: DCQLQuery? = null,

    @SerialName("request_uri_method")
    val requestUriMethod: String? = null,

    @SerialName("transaction_data")
    val transactionData: List<String>? = null,

    @SerialName("verifier_info")
    val verifierInfo: JsonObject? = null,
) {

    fun toHttpParameters(): String {
        val sb = StringBuilder()
        sb.append("client_id=${clientId}")
        sb.append("&response_type=$responseType")
        redirectUri?.also {
            sb.append("&redirect_uri=${redirectUri}")
        }
        responseMode?.also {
            sb.append("&response_mode=${responseMode}")
        }
        responseUri?.also {
            sb.append("&response_uri=${responseUri}")
        }
        scope?.also {
            sb.append("&scope=${urlEncode(it)}")
        }
        authorizationDetails?.also {
            val json = Json.encodeToString(it)
            sb.append("&authorization_details=${urlEncode(json)}")
        }
        dcqlQuery?.also {
            val json = Json.encodeToString(it)
            sb.append("&dcql_query=${urlEncode(json)}")
        }
        codeChallenge?.also {
            sb.append("&code_challenge=${urlEncode(it)}")
        }
        codeChallengeMethod?.also {
            sb.append("&code_challenge_method=${urlEncode(it)}")
        }
        return sb.toString()
    }

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true }
        fun fromJson(json: String) = jsonInst.decodeFromString<AuthorizationRequestV10>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<AuthorizationRequestV10>(json)

        fun fromHttpParameters(params: Map<String, String>): AuthorizationRequestV10 {

            val authReq = AuthorizationRequestV10(
                clientId = params["client_id"] ?: error("No client_id"),
                redirectUri = params["redirect_uri"],
                responseType = params["response_type"] ?: error("No response_type"),
                responseMode = params["response_mode"],
                responseUri = params["response_uri"],
                nonce = params["nonce"],
                scope = params["scope"],
                state = params["state"],
                authorizationDetails = params["authorization_details"]?.let {
                    Json.decodeFromString<List<AuthorizationDetail>>(it)
                },
                codeChallenge = params["code_challenge"],
                codeChallengeMethod = params["code_challenge_method"],
                clientMetadata = params["client_metadata"]?.let {
                    Json.decodeFromString<ClientMetadata>(it)
                },
                dcqlQuery = params["dcql_query"]?.let {
                    Json.decodeFromString<DCQLQuery>(it)
                },
                requestUriMethod = params["request_uri_method"],
                transactionData = params["transaction_data"]?.let {
                    Json.decodeFromString<List<String>>(it)
                },
                verifierInfo = params["verifier_info"]?.let {
                    Json.decodeFromString<JsonObject>(it)
                },
            )
            return authReq
        }
    }

    private fun urlEncode(json: String) =
        URLEncoder.encode(json, StandardCharsets.UTF_8)

    @Serializable
    data class AuthorizationDetail(
        val type: String,  // must be "openid_credential"
        @SerialName("credential_configuration_id")
        val credentialConfigurationId: String,
        val format: String? = null,
        val types: List<String>? = null,
        val locations: List<String>? = null,
    )

    @Serializable
    data class ClientMetadata(
        val type: String,  // must be "openid_credential"
        @SerialName("credential_configuration_id")
        val credentialConfigurationId: String,
        val format: String? = null,
        val types: List<String>? = null,
        val locations: List<String>? = null,
    )
}

// DCQLQuery ===================================================================================================================================================

/**
 * A Credential Query is an object representing a request for a presentation of one or more matching Credentials.
 * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-credential-query
 */
@Serializable
data class DCQLQuery(
    val credentials: List<CredentialQuery>,
    @SerialName("credential_sets")
    val credentialSets: List<CredentialSet>? = null,
) {
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true }
        fun fromJson(json: String): DCQLQuery = jsonInst.decodeFromString(json)
        fun fromJson(json: JsonObject): DCQLQuery = jsonInst.decodeFromJsonElement(json)
    }
}

@Serializable
data class CredentialSet(
    val options: List<List<String>>,
    val required: Boolean? = null,
)

@Serializable
data class CredentialQuery(
    val id: String,
    val format: String,
    val multiple: Boolean? = null,
    val meta: QueryMeta,
    @SerialName("trusted_authorities")
    val trustedAuthorities: List<TrustedAuthority>? = null,
    @SerialName("require_cryptographic_holder_binding")
    val requireCryptographicHolderBinding: Boolean? = null,
    val claims: List<QueryClaim>? = null,
    @SerialName("claim_sets")
    val claimSets: List<List<String>>? = null,
)

@Serializable
data class QueryClaim(
    val path: List<String>,
    val values: List<JsonElement>,
)

@Serializable
data class QueryMeta(
    @SerialName("vct_values")
    val vctValues: List<String>,
)

@Serializable
data class TrustedAuthority(
    val type: String,
    val values: List<String>,
)

class AuthorizationRequestV10Builder {

    val log = KotlinLogging.logger {}

    lateinit var clientId: String
    lateinit var codeVerifier: String

    private var clientState: String? = null
    private var codeChallengeMethod: String? = null
    private var dcqlQuery: DCQLQuery? = null
    private var metadata: IssuerMetadata? = null
    private var responseType = "code"
    private var responseMode: String? = null
    private var redirectUri: String? = null
    private var responseUri: String? = null

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

    fun withResponseMode(responseMode: String): AuthorizationRequestV10Builder {
        this.responseMode = responseMode
        return this
    }

    fun withResponseUri(responseUri: String): AuthorizationRequestV10Builder {
        this.responseUri = responseUri
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
            responseMode = responseMode,
            responseType = responseType,
            responseUri = responseUri,
        )

        when(responseMode) {
            "direct_post" -> require(redirectUri == null && responseUri != null) { "No response_uri" }
            else -> require(redirectUri != null && responseUri == null) { "No redirect_uri" }
        }

        log.info { "AuthorizationRequest: ${authReq.toJson()}" }
        return authReq
    }
}