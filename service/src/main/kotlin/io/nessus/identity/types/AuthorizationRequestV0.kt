package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class AuthorizationRequestV0(

    @SerialName("client_id")
    override val clientId: String,

    @SerialName("redirect_uri")
    override val redirectUri: String? = null,

    @SerialName("response_type")
    override val responseType: String? = null,

    @SerialName("response_mode")
    override val responseMode: String? = null,

    @SerialName("request")
    override val request: String? = null,

    @SerialName("request_uri")
    override val requestUri: String? = null,

    @SerialName("response_uri")
    override val responseUri: String? = null,

    @SerialName("nonce")
    override val nonce: String? = null,

    @SerialName("scope")
    override val scope: String? = null,

    @SerialName("state")
    override val state: String? = null,

    @SerialName("code_challenge")
    override val codeChallenge: String? = null,

    @SerialName("code_challenge_method")
    override val codeChallengeMethod: String? = null,

    // Request Parameters defined in "OpenID for Verifiable Presentations 1.0"
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters

    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetail>? = null,

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

): AuthorizationRequest() {

    override fun toRequestParameters(): Map<String, List<String>> {
        return buildMap {
            putAll(super.toRequestParameters())
            authorizationDetails?.also {
                val json = Json.encodeToString(it)
                put("authorization_details", listOf(json))
            }
            dcqlQuery?.also {
                val json = Json.encodeToString(it)
                put("dcql_query", listOf(json))
            }
        }
    }

    override fun toJson() = Json.encodeToString(this)
    override fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true }
        fun fromJson(json: String) = jsonInst.decodeFromString<AuthorizationRequestV0>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<AuthorizationRequestV0>(json)

        fun fromHttpParameters(params: Map<String, String>): AuthorizationRequestV0 {
            return AuthorizationRequestV0(
                clientId = params["client_id"] ?: error("No client_id"),
                redirectUri = params["redirect_uri"],
                responseType = params["response_type"] ?: error("No response_type"),
                responseMode = params["response_mode"],
                request = params["request"],
                requestUri = params["request_uri"],
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
        }
    }

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

// AuthorizationDetails ================================================================================================

@Serializable
data class AuthorizationDetail(

    /** Always "openid_credential" for credential issuance */
    val type: String,

    /** Optional: the credential configuration that this access token authorizes */
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,

    /** Optional: array of credential identifiers available under this token */
    @SerialName("credential_identifiers")
    val credentialIdentifiers: List<String>? = null,

    /** Optional: credential format (e.g. "jwt_vc_json") */
    val format: String? = null,

    /** Optional: where to send subsequent credential requests */
    val locations: List<String>? = null,

    /** Optional: human-readable or UI display data */
    val display: JsonElement? = null,

    /** Optional: credential type (e.g. "UniversityDegreeCredential") */
    @SerialName("credential_type")
    val credentialType: String? = null,
)

// DCQLQuery ===========================================================================================================

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
