package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable(with = VCDataJwtSerializer::class)
sealed class VCDataJwt {
    abstract val iss: String?
    abstract val sub: String?
    abstract val jti: String?

    abstract val vcId: String
    abstract val types: List<String>

    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }

    companion object {
        fun fromEncoded(encoded: String): VCDataJwt {
            val vcJwt = SignedJWT.parse(encoded)
            val decJwt = Json.decodeFromString<VCDataJwt>("${vcJwt.payload}")
            if (decJwt is VCDataSdV11Jwt) {
                decJwt.decodeDisclosures(encoded)
            }
            return decJwt
        }
    }
}

object VCDataJwtSerializer : JsonContentPolymorphicSerializer<VCDataJwt>(VCDataJwt::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<VCDataJwt> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("_sd") -> VCDataSdV11Jwt.serializer()
            else -> VCDataV11Jwt.serializer()
        }
    }
}