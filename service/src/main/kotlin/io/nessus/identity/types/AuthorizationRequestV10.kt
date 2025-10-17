package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

@Serializable
data class AuthorizationRequestV10(

    @SerialName("client_id")
    val clientId: String,

    @SerialName("redirect_uri")
    val redirectUri: String,

    @SerialName("response_type")
    val responseType: String,

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
    val clientMetadata: JsonObject? = null,

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
        sb.append("&redirect_uri=${redirectUri}")
        sb.append("&response_type=$responseType")
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
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<AuthorizationRequestV10>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<AuthorizationRequestV10>(json)
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
