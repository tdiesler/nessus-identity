package io.nessus.identity.types

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.service.http
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = IssuerMetadataSerializer::class)
abstract class IssuerMetadata {
    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
    abstract val supportedCredentialScopes: Set<String>

    private lateinit var authMetadata: JsonObject

    fun getAuthorizationMetadata(): JsonObject {
        if (!::authMetadata.isInitialized) {
            val authServerUrl = when(this) {
                is IssuerMetadataDraft11 -> authorizationServer!!
                is IssuerMetadataV0 -> authorizationServers!!.first()
                else -> throw IllegalStateException("Unsupported IssuerMetadata type")
            }
            runBlocking {
                val res = http.get("$authServerUrl/.well-known/openid-configuration")
                authMetadata = res.body<JsonObject>()
            }
        }
        return authMetadata
    }

    fun getAuthorizationEndpoint(): String {
        return getAuthorizationMetadata().getValue("authorization_endpoint").jsonPrimitive.content
    }

    fun getAuthorizationTokenEndpoint(): String {
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
            jsonObj.containsKey("credential_configurations_supported") -> IssuerMetadataV0.serializer()
            else -> throw SerializationException("Unknown CredentialEntry type: $element")
        }
    }
}

abstract class CredentialConfiguration {
    abstract val format: String
    abstract val cryptographicBindingMethodsSupported: List<String>?
    abstract fun toJson(): String
    abstract fun toJsonObj(): JsonObject
}