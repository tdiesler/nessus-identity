package io.nessus.identity.types

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

typealias WaltIdCredentialResponse = id.walt.oid4vc.responses.CredentialResponse

@Serializable(with = CredentialResponseSerializer::class)
sealed class CredentialResponse {

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<CredentialResponse>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<CredentialResponse>(json)
    }
}

object CredentialResponseSerializer : JsonContentPolymorphicSerializer<CredentialResponse>(CredentialResponse::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialResponse> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("acceptance_token") || jsonObj.containsKey("credential") -> CredentialResponseDraft11.serializer()
            jsonObj.containsKey("credentials") -> CredentialResponseV0.serializer()
            else -> throw SerializationException("Unknown CredentialResponse type: $element")
        }
    }
}
