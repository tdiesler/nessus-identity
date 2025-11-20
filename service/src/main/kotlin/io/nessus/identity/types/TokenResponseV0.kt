package io.nessus.identity.types

import id.walt.oid4vc.data.dif.PresentationSubmission
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class TokenResponseV0(

    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetail>? = null,

    // Optional fields per OpenID4VCI
    @SerialName("c_nonce")
    val cNonce: String? = null,

    @SerialName("c_nonce_expires_in")
    val cNonceExpiresIn: Long? = null,

    @SerialName("access_token")
    val accessToken: String? = null,

    @SerialName("expires_in")
    val expiresIn: Long? = null,

    @SerialName("id_token")
    val idToken: String? = null,

    @SerialName("not-before-policy")
    val notBeforePolicy: Long? = null,

    @SerialName("presentation_submission")
    val presentationSubmission: PresentationSubmission? = null,

    @SerialName("refresh_expires_in")
    val refreshExpiresIn: Long? = null,

    @SerialName("refresh_token")
    val refreshToken: String? = null,

    @SerialName("scope")
    val scope: String? = null,

    @SerialName("session_state")
    val sessionState: String? = null,

    @SerialName("state")
    val state: String? = null,

    @SerialName("token_type")
    val tokenType: String? = null,

    @SerialName("vp_token")
    val vpToken: String? = null,
) {
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<TokenResponseV0>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<TokenResponseV0>(json)
    }
}
