package io.nessus.identity.types

import io.ktor.client.call.body
import io.ktor.client.request.get
import io.nessus.identity.service.http
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
import kotlinx.serialization.json.jsonPrimitive

@Serializable(with = IssuerMetadataSerializer::class)
abstract class IssuerMetadata {
    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
    abstract val supportedTypes: Set<String>

    private lateinit var authMetadata: JsonObject

    suspend fun getAuthorizationMetadata(): JsonObject {
        if (!::authMetadata.isInitialized) {
            val authServerUrl = when(this) {
                is IssuerMetadataDraft11 -> authorizationServer!!
                is IssuerMetadataDraft17 -> authorizationServers!!.first()
                else -> throw IllegalStateException("Unsupported IssuerMetadata type")
            }
            val res = http.get("$authServerUrl/.well-known/openid-configuration")
            authMetadata = res.body<JsonObject>()
        }
        return authMetadata
    }

    suspend fun getAuthorizationAuthEndpoint(): String {
        return getAuthorizationMetadata().getValue("authorization_endpoint").jsonPrimitive.content
    }

    suspend fun getAuthorizationTokenEndpoint(): String {
        return getAuthorizationMetadata().getValue("token_endpoint").jsonPrimitive.content
    }

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