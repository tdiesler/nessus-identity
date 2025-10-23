package io.nessus.identity.types

import id.walt.oid4vc.data.OpenIDProviderMetadata
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-w3c-verifiable-credentials
*/
@Serializable
@OptIn(ExperimentalSerializationApi::class)
data class IssuerMetadataDraft11(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credential_endpoint")
    override val credentialEndpoint: String,

    @SerialName("authorization_server")
    val authorizationServer: String? = null,

    @SerialName("batch_credential_endpoint")
    val batchCredentialEndpoint: String? = null,

    // Not in the spec, but still used by EBSI CT v3.2
    @SerialName("deferred_credential_endpoint")
    val deferredCredentialEndpoint: String? = null,

    @SerialName("credentials_supported")
    val credentialsSupported: List<CredentialConfigurationDraft11>,

    @SerialName("display")
    val display: List<IssuerDisplay>? = null
) : IssuerMetadata() {
    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<IssuerMetadataDraft11>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<IssuerMetadataDraft11>(json)
    }

    override val supportedTypes
        get() = credentialsSupported.flatMap { it.types ?: emptyList() }.toSet()

    fun toWaltIdIssuerMetadata(): OpenIDProviderMetadata {
        val jsonStr = Json.encodeToString(this)
        return OpenIDProviderMetadata.fromJSONString(jsonStr)
    }
}

@Serializable
data class IssuerDisplay(
    val name: String? = null,
    val locale: String? = null
)

@Serializable
@OptIn(ExperimentalSerializationApi::class)
data class CredentialConfigurationDraft11(
    @SerialName("format")
    override val format: String,

    @SerialName("id")
    val id: String? = null,

    // Required for jwt_vc_json
    @SerialName("types")
    val types: List<String>? = null,

    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,

    @SerialName("cryptographic_suites_supported")
    val cryptographicSuitesSupported: List<String>? = null,

    @SerialName("credentialSubject")
    val credentialSubject: Map<String, SubjectMetadataDraft11>? = null,

    @SerialName("display")
    val display: List<CredentialDisplay>? = null
): CredentialConfiguration() {
    override fun toJson() = Json.encodeToString(this)
    override fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject
}

@Serializable
data class SubjectMetadataDraft11(
    @SerialName("mandatory")
    val mandatory: Boolean? = null,
    @SerialName("value_type")
    val valueType: String? = null,
    @SerialName("display")
    val display: List<SubjectDisplayDraft11>? = null
)

@Serializable
data class SubjectDisplayDraft11(
    val name: String? = null,
    val locale: String? = null,
    val description: String? = null
)
