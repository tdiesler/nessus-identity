package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

abstract class CredentialOffer {
    abstract val credentialIssuer: String
    abstract val grants: Grants?

    abstract fun getCredentialTypes(): List<String>

    fun getAuthorizationCodeGrant() : AuthorizationCodeGrant? {
        return grants?.authorizationCode
    }

    fun getPreAuthorizedCodeGrant() : PreAuthorizedCodeGrant? {
        return grants?.preAuthorizedCode
    }

    abstract fun toJson() : String
    abstract fun toJsonObj() : JsonObject
}

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
*/
@Serializable
data class CredentialOfferDraft17(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,

    @SerialName("grants")
    override val grants: Grants? = null
) : CredentialOffer() {

    companion object {
        fun fromJson(json: String) = Json.decodeFromString<CredentialOfferDraft17>(json)
        fun fromJson(json: JsonObject) = Json.decodeFromJsonElement<CredentialOfferDraft17>(json)
    }

    // [TODO] Remove when Draft11 is gone
    override fun getCredentialTypes(): List<String> {
        return credentialConfigurationIds
    }

    override fun toJson() = Json.encodeToString(this)
    override fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject
}

@Serializable
data class Grants(
    @SerialName("authorization_code")
    val authorizationCode: AuthorizationCodeGrant? = null,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: PreAuthorizedCodeGrant? = null
)

@Serializable
data class AuthorizationCodeGrant(
    @SerialName("issuer_state")
    val issuerState: String? = null,

    @SerialName("authorization_server")
    val authorizationServer: String? = null
)

@Serializable
data class PreAuthorizedCodeGrant(
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String,

    @SerialName("tx_code")
    val txCode: TransactionCode? = null
)

@Serializable
data class TransactionCode(
    val length: Int? = null,
    @SerialName("input_mode")
    val inputMode: String? = null,
    val description: String? = null
)
