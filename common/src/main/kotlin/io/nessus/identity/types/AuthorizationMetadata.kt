package io.nessus.identity.types

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*


@Serializable(with = AuthorizationMetadataSerializer::class)
class AuthorizationMetadata(val jsonObj: JsonObject) {

    fun getAuthorizationEndpointUri(): String {
        return jsonObj.getValue("authorization_endpoint").jsonPrimitive.content
    }

    fun getAuthorizationTokenEndpointUri(): String {
        return jsonObj.getValue("token_endpoint").jsonPrimitive.content
    }
}

object AuthorizationMetadataSerializer : KSerializer<AuthorizationMetadata> {
    override val descriptor = JsonObject.serializer().descriptor
    override fun deserialize(decoder: Decoder): AuthorizationMetadata {
        val json = decoder.decodeSerializableValue(JsonObject.serializer())
        return AuthorizationMetadata(json)
    }
    override fun serialize(encoder: Encoder, value: AuthorizationMetadata) {
        encoder.encodeSerializableValue(JsonObject.serializer(), value.jsonObj)
    }
}