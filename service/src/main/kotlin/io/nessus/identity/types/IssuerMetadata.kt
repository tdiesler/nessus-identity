package io.nessus.identity.types

import id.walt.oid4vc.data.CredentialFormat
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.service.http
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = IssuerMetadataSerializer::class)
sealed class IssuerMetadata {

    abstract val credentialIssuer: String
    abstract val credentialEndpoint: String
    abstract val deferredCredentialEndpoint: String?
    abstract val supportedCredentialScopes: Set<String>

    private lateinit var authMetadata: JsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<IssuerMetadata>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<IssuerMetadata>(json)
    }
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    fun getAuthorizationMetadata(): JsonObject {
        if (!::authMetadata.isInitialized) {
            val authServerUrl = when(this) {
                is IssuerMetadataDraft11 -> authorizationServer!!
                is IssuerMetadataV0 -> authorizationServers!!.first()
            }
            runBlocking {
                val res = http.get("$authServerUrl/.well-known/openid-configuration")
                authMetadata = res.body<JsonObject>()
            }
        }
        return authMetadata
    }

    fun getAuthorizationEndpointUri(): String {
        return getAuthorizationMetadata().getValue("authorization_endpoint").jsonPrimitive.content
    }

    fun getAuthorizationTokenEndpointUri(): String {
        return getAuthorizationMetadata().getValue("token_endpoint").jsonPrimitive.content
    }

    abstract fun getCredentialScope(credType: String): String?

    abstract fun getCredentialFormat(credType: String): CredentialFormat?
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