package io.nessus.identity.types

import com.nimbusds.jose.jwk.JWK
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.utils.http
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

    fun getIssuer(): String {
        return jsonObj.getValue("issuer").jsonPrimitive.content
    }

    fun getJwksUri(): String {
        return jsonObj.getValue("jwks_uri").jsonPrimitive.content
    }

    suspend fun getJwks(): List<JWK> {
        val jwksMetadata = http.get(getJwksUri()).body<JsonObject>()
        val jwks = jwksMetadata.getValue("keys").jsonArray
            .map { it.jsonObject.toString() }
            .map { JWK.parse(it)}
        return jwks
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