package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable(with = VCDataJwtSerializer::class)
sealed class W3CCredentialJwt {
    abstract val iss: String?
    abstract val sub: String?
    abstract val jti: String?

    abstract val vcId: String
    abstract val types: List<String>

    companion object {
        fun fromEncoded(encoded: String): W3CCredentialJwt {
            val sigJwt = SignedJWT.parse(encoded)
            val credJwt = Json.decodeFromString<W3CCredentialJwt>("${sigJwt.payload}")
            if (credJwt is W3CCredentialSdV11Jwt) {
                credJwt.decodeDisclosures(encoded)
            }
            return credJwt
        }
    }

    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }
}

object VCDataJwtSerializer : JsonContentPolymorphicSerializer<W3CCredentialJwt>(W3CCredentialJwt::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<W3CCredentialJwt> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("_sd") -> W3CCredentialSdV11Jwt.serializer()
            else -> W3CCredentialV11Jwt.serializer()
        }
    }
}