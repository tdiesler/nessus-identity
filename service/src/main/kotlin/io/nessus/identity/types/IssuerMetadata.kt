package io.nessus.identity.types

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable(with = IssuerMetadataSerializer::class)
abstract class IssuerMetadata {
    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
    abstract val supportedTypes: Set<String>

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<IssuerMetadata>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<IssuerMetadata>(json)
    }

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject
}

object IssuerMetadataSerializer : JsonContentPolymorphicSerializer<IssuerMetadata>(IssuerMetadata::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<IssuerMetadata> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("credentials_supported") -> IssuerMetadataDraft11.serializer()
            jsonObj.containsKey("credential_configurations_supported") -> IssuerMetadataDraft17.serializer()
            else -> throw SerializationException("Unknown CredentialEntry type: $element")
        }
    }
}

abstract class CredentialConfiguration {
    abstract val format: String
    abstract val cryptographicBindingMethodsSupported: List<String>?
}