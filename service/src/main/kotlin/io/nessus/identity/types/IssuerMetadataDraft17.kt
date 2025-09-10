package io.nessus.identity.types

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
*/
@Serializable
data class IssuerMetadataDraft17(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credential_endpoint")
    override val credentialEndpoint: String,

    @SerialName("authorization_servers")
    val authorizationServers: List<String>? = null,

    @SerialName("nonce_endpoint")
    val nonceEndpoint: String? = null,

    @SerialName("deferred_credential_endpoint")
    val deferredCredentialEndpoint: String? = null,

    @SerialName("notification_endpoint")
    val notificationEndpoint: String? = null,

    @SerialName("credential_request_encryption")
    val credentialRequestEncryption: CredentialRequestEncryption? = null,

    @SerialName("credential_response_encryption")
    val credentialResponseEncryption: CredentialResponseEncryption? = null,

    @SerialName("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfiguration>
) : IssuerMetadata() {
    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<IssuerMetadataDraft17>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<IssuerMetadataDraft17>(json)
    }

    override val supportedTypes
        get() = credentialConfigurationsSupported.keys
}

@Serializable
data class CredentialRequestEncryption(
    val jwks: JsonElement,
    @SerialName("enc_values_supported")
    val encValuesSupported: List<String>
)

@Serializable
data class CredentialResponseEncryption(
    @SerialName("alg_values_supported")
    val algValuesSupported: List<String>,

    @SerialName("enc_values_supported")
    val encValuesSupported: List<String>,

    @SerialName("zip_values_supported")
    val zipValuesSupported: List<String>? = null,

    @SerialName("encryption_required")
    val encryptionRequired: Boolean
)

@Serializable
@OptIn(ExperimentalSerializationApi::class)
data class CredentialConfiguration(
    val format: String,
    val scope: String? = null,

    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgValuesSupported: List<String>? = null,

    @SerialName("cryptographic_binding_methods_supported")
    val cryptographicBindingMethodsSupported: List<String>? = null,

    @SerialName("proof_types_supported")
    val proofTypesSupported: Map<String, ProofTypeMetadata>? = null,

    @SerialName("credential_metadata")
    val credentialMetadata: CredentialMetadata? = null,

    val claims: List<ClaimDescription>? = null,

    // captures non-standard fields like id, vct, credential_definition
    val extras: Map<String, JsonElement>? = null
)

@Serializable
data class ProofTypeMetadata(
    @SerialName("proof_signing_alg_values_supported")
    val proofSigningAlgValuesSupported: List<String>,

    @SerialName("key_attestations_required")
    val keyAttestationsRequired: KeyAttestationsRequired? = null
)

@Serializable
data class KeyAttestationsRequired(
    @SerialName("key_storage")
    val keyStorage: List<String>? = null,

    @SerialName("user_authentication")
    val userAuthentication: List<String>? = null
)

@Serializable
data class CredentialMetadata(
    val display: List<CredentialDisplay>? = null,
    val claims: List<ClaimDescription>? = null
)

@Serializable
data class CredentialDisplay(
    val name: String,
    val locale: String? = null,
    val logo: Logo? = null,
    val description: String? = null,

    @SerialName("background_color")
    val backgroundColor: String? = null,

    @SerialName("background_image")
    val backgroundImage: BackgroundImage? = null,

    @SerialName("text_color")
    val textColor: String? = null
)

@Serializable
data class Logo(
    val uri: String,
    @SerialName("alt_text")
    val altText: String? = null
)

@Serializable
data class BackgroundImage(
    val uri: String
)

/**
 * Appendix B.2 Claim Description
 */
@Serializable
data class ClaimDescription(
    val path: List<String>,
    val mandatory: Boolean? = null,
    val display: List<ClaimDisplay>? = null,
    @SerialName("value_type")
    val valueType: String? = null
)

@Serializable
data class ClaimDisplay(
    val name: String? = null,
    val locale: String? = null,
    val description: String? = null
)
