package io.nessus.identity.types

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

@Serializable
data class CredentialRequestV10(
    @SerialName("credential_identifier")
    val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id")
    val credentialConfigurationId: String? = null,
    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryption? = null,
    @SerialName("proofs")
    val proofs: Proofs? = null,
) {

    @Serializable
    data class CredentialResponseEncryption(
        val jwk: JsonObject,
        val enc: String,
        val zip: String? = null
    )

    @Serializable
    data class Proofs(
        val jwt: List<String>? = null,
        val di_vp: List<JsonElement>? = null,
        val attestation: List<String>? = null
    )
}