package io.nessus.identity.types

import kotlinx.serialization.Contextual
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull
import kotlin.time.Instant

@Serializable
data class VerifiableCredentialV11Jwt(
    val sub: String,
    val iss: String,
    val jti: String? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    var exp: Long? = null,
    val vc: VerifiableCredentialV11,
) {
    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }
}

// VC-Data Model v1.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#VC_DATA
// https://www.w3.org/TR/2022/REC-vc-data-model-20220303
@Serializable
data class VerifiableCredentialV11(
    @SerialName("@context")
    val context: List<String> = listOf("https://www.w3.org/2018/credentials/v1"),
    val id: String? = null,
    val type: List<String> = listOf("VerifiableCredential"),
    val issuer: Issuer,
    @Serializable(with = TimeInstantIso8601Serializer::class)
    val issuanceDate: Instant,
    @Serializable(with = TimeInstantIso8601Serializer::class)
    val expirationDate: Instant? = null,
    val credentialSubject: CredentialSubjectV11,
    val credentialStatus: CredentialStatusV11? = null,
    val credentialSchema: CredentialSchemaV11? = null,
    // [TODO #292] Keycloak sends no proof element in VerifiableCredential
    // https://github.com/tdiesler/nessus-identity/issues/292
    val proof: Proof? = null
) {
    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }
}

@Serializable(with = IssuerSerializer::class)
data class Issuer(
    val id: String,
    /** optional additional fields for issuer (e.g. did methods, service endpoints) */
    @Contextual
    // @JsonNames  // pseudo-annotation idea; else fallback map
    val extras: Map<String, JsonElement> = emptyMap()
)

/**
 * https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#credential-subject
 */
@Serializable(with = CredentialSubjectV11Serializer::class)
data class CredentialSubjectV11(
    val id: String? = null,
    val claims: Map<String, JsonElement> = emptyMap()
)

@Serializable
data class CredentialStatusV11(
    val id: String,
    val type: String,
    /** extra fields if any */
    val extras: Map<String, JsonElement> = emptyMap()
)

@Serializable
data class CredentialSchema(
    val id: String,
    val type: String,
    /** other schema properties if any */
    val extras: Map<String, JsonElement> = emptyMap()
)

@Serializable
data class Proof(
    val type: String,
    val created: String,            // or Instant with serializer
    val proofPurpose: String,
    val verificationMethod: String,
    @SerialName("jws")
    val jws: String? = null,
    @SerialName("proofValue")
    val proofValue: String? = null,
    /** optional other proof fields, so a fallback map */
    val extras: Map<String, JsonElement> = emptyMap()
)

object CredentialSubjectV11Serializer : KSerializer<CredentialSubjectV11> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("CredentialSubjectV11") {
            element<String>("id", isOptional = true)
        }

    override fun serialize(encoder: Encoder, value: CredentialSubjectV11) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: error("CredentialSubjectV11Serializer only works with JSON")

        val obj = buildJsonObject {
            value.id?.let { put("id", JsonPrimitive(it)) }
            value.claims.forEach { (k, v) -> put(k, v) }
        }
        jsonEncoder.encodeJsonElement(obj)
    }

    override fun deserialize(decoder: Decoder): CredentialSubjectV11 {
        val jsonDecoder = decoder as? JsonDecoder
            ?: error("CredentialSubjectV11Serializer only works with JSON")

        val obj = jsonDecoder.decodeJsonElement()
        require(obj is JsonObject) { "CredentialSubject must be a JSON object" }

        val id = obj["id"]?.jsonPrimitive?.contentOrNull
        val claims = obj.filterKeys { it != "id" }
        return CredentialSubjectV11(id, claims)
    }
}

object IssuerSerializer : KSerializer<Issuer> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("Issuer") {
            element<String>("id", isOptional = true)
        }

    override fun serialize(encoder: Encoder, value: Issuer) {
        val jsonEncoder = encoder as? JsonEncoder ?: error("No a JsonEncoder")
        val json = buildJsonObject {
            put("id", JsonPrimitive(value.id))
            value.extras.forEach { (k, v) -> put(k, v) }
        }
        jsonEncoder.encodeJsonElement(json)
    }

    override fun deserialize(decoder: Decoder): Issuer {
        val jsonDecoder = decoder as? JsonDecoder ?: error("No a JsonDecoder")
        val element = jsonDecoder.decodeJsonElement()
        return when (element) {
            is JsonPrimitive -> Issuer(element.content)
            is JsonObject -> {
                val id = element["id"]?.jsonPrimitive?.content
                    ?: error("Issuer object must contain 'id'")
                val extras = element - "id"
                Issuer(id, extras)
            }
            else -> error("Invalid issuer format: $element")
        }
    }
}

object TimeInstantIso8601Serializer : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeString(value.toString()) // ISO 8601 UTC format
    }

    // [TODO #291] Keycloak sends issuanceDate as numeric value rather than Iso8601 string
    // https://github.com/tdiesler/nessus-identity/issues/291
    override fun deserialize(decoder: Decoder): Instant {
        val jsonDecoder = decoder as? JsonDecoder ?: error("No a JsonDecoder")
        val el = jsonDecoder.decodeJsonElement().jsonPrimitive
        return when {
            el.isString -> Instant.parse(el.content)
            el.longOrNull != null -> Instant.fromEpochSeconds(el.long)
            el.doubleOrNull != null -> Instant.fromEpochSeconds(el.double.toLong())
            else -> error("Unexpected JSON for Instant: $el")
        }
    }
}