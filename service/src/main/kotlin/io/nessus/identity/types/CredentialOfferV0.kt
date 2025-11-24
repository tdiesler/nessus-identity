package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
*/
@Serializable
data class CredentialOfferV0(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credential_configuration_ids")
    override val credentialConfigurationIds: List<String>,

    @SerialName("grants")
    override val grants: Grants? = null
) : CredentialOffer() {

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<CredentialOfferV0>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<CredentialOfferV0>(json)
    }
}
