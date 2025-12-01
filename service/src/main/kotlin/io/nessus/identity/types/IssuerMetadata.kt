package io.nessus.identity.types

import id.walt.oid4vc.data.CredentialFormat
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.json.*

@Serializable(with = IssuerMetadataSerializer::class)
sealed class IssuerMetadata {

    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
    abstract val deferredCredentialEndpoint: String?
    abstract val supportedCredentialScopes: Set<String>

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<IssuerMetadata>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<IssuerMetadata>(json)
    }
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    @Transient
    protected var authMetadata: AuthorizationMetadata? = null

    fun withAuthorizationMetadata(authMetadata: AuthorizationMetadata): IssuerMetadata {
        this.authMetadata = authMetadata
        return this
    }

    abstract suspend fun getAuthorizationMetadata(): AuthorizationMetadata

    abstract fun getCredentialScope(configId: String): String?

    abstract fun getCredentialFormat(configId: String): CredentialFormat?
}

object IssuerMetadataSerializer : JsonContentPolymorphicSerializer<IssuerMetadata>(IssuerMetadata::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<IssuerMetadata> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("credentials_supported") -> IssuerMetadataDraft11.serializer()
            jsonObj.containsKey("credential_configurations_supported") -> IssuerMetadataV0.serializer()
            else -> throw SerializationException("Unknown IssuerMetadata type: $element")
        }
    }
}

abstract class CredentialConfiguration {
    abstract val format: String
    abstract val cryptographicBindingMethodsSupported: List<String>?
    abstract fun toJson(): String
    abstract fun toJsonObj(): JsonObject
}