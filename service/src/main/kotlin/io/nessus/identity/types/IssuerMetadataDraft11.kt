package io.nessus.identity.types

import id.walt.oid4vc.data.OpenIDProviderMetadata
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

abstract class IssuerMetadata {
    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
}

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-w3c-verifiable-credentials
*/
@Serializable
@JsonIgnoreUnknownKeys
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
    val credentialsSupported: List<CredentialSupportedDraft11>,

    val display: List<IssuerDisplay>? = null
) : IssuerMetadata() {
    companion object {
        fun fromJson(json: String) : IssuerMetadataDraft11 {
            return Json.decodeFromString(json)
        }
    }

    fun toOpenIDProviderMetadata() : OpenIDProviderMetadata {
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
@JsonIgnoreUnknownKeys
@OptIn(ExperimentalSerializationApi::class)
data class CredentialSupportedDraft11(
    val format: String,

    val id: String? = null,

    // Required for jwt_vc_json
    val types: List<String>? = null,

    @SerialName("cryptographic_binding_methods_supported")
    val cryptographicBindingMethodsSupported: List<String>? = null,

    @SerialName("cryptographic_suites_supported")
    val cryptographicSuitesSupported: List<String>? = null,

    @SerialName("credentialSubject")
    val credentialSubject: Map<String, SubjectMetadataDraft11>? = null,

    val display: List<CredentialDisplay>? = null
)

@Serializable
data class SubjectMetadataDraft11(
    val mandatory: Boolean? = null,
    @SerialName("value_type")
    val valueType: String? = null,

    val display: List<SubjectDisplayDraft11>? = null
)

@Serializable
data class SubjectDisplayDraft11(
    val name: String? = null,
    val locale: String? = null,
    val description: String? = null
)
