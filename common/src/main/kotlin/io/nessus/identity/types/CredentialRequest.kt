package io.nessus.identity.types

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = CredentialRequestSerializer::class)
sealed class CredentialRequest {

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject
}

object CredentialRequestSerializer : JsonContentPolymorphicSerializer<CredentialRequest>(CredentialRequest::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialRequest> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("proof") -> CredentialRequestDraft11.serializer()
            jsonObj.containsKey("proofs") -> CredentialRequestV0.serializer()
            else -> throw SerializationException("Unknown CredentialRequest type: $element")
        }
    }
}
