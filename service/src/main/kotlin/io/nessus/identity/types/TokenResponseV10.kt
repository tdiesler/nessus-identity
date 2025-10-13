package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable
data class TokenResponseV10(

    @SerialName("token_type")
    val tokenType: String,

    @SerialName("access_token")
    val accessToken: String,

    @SerialName("expires_in")
    val expiresIn: Long? = null,

    @SerialName("refresh_token")
    val refreshToken: String? = null,

    @SerialName("refresh_expires_in")
    val refreshExpiresIn: Long? = null,

    @SerialName("id_token")
    val idToken: String? = null,

    @SerialName("scope")
    val scope: String? = null,

    @SerialName("session_state")
    val sessionState: String? = null,

    @SerialName("not-before-policy")
    val notBeforePolicy: Long? = null,

    @SerialName("authorization_details")
    val authorizationDetails: AuthorizationDetails? = null,

    // Optional fields per OpenID4VCI
    @SerialName("c_nonce")
    val cNonce: String? = null,

    @SerialName("c_nonce_expires_in")
    val cNonceExpiresIn: Long? = null,
) {
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<TokenResponseV10>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<TokenResponseV10>(json)
    }

    @Serializable
    data class AuthorizationDetails(
        /** Always "openid_credential" for credential issuance */
        val type: String,

        /** Optional: the credential configuration that this access token authorizes */
        @SerialName("credential_configuration_id")
        val credentialConfigurationId: String? = null,

        /** Optional: credential type (e.g. "UniversityDegreeCredential") */
        @SerialName("credential_type")
        val credentialType: String? = null,

        /** Optional: credential format (e.g. "jwt_vc_json") */
        val format: String? = null,

        /** Optional: array of credential identifiers available under this token */
        @SerialName("credential_identifiers")
        val credentialIdentifiers: List<String>? = null,

        /** Optional: where to send subsequent credential requests */
        val locations: List<String>? = null,

        /** Optional: human-readable or UI display data */
        val display: JsonElement? = null,
    )
}
