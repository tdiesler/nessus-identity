package io.nessus.identity.types

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import kotlin.time.Instant
import kotlin.uuid.Uuid

// VCDataV11 ===================================================================================================================================================

// VC-Data Model v1.1
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#VC_DATA
// https://www.w3.org/TR/2022/REC-vc-data-model-20220303

@Serializable
data class VCDataV11(
    val id: String? = null,
    @SerialName("@context")
    val context: List<String>,
    val type: List<String>,
    @Serializable(with = IssuerSerializer::class)
    val issuer: Issuer,
    @Serializable(with = TimeInstantSerializer::class)
    val issuanceDate: Instant,
    @Serializable(with = TimeInstantSerializer::class)
    val expirationDate: Instant? = null,
    @Serializable(with = CredentialSchemaSerializer::class)
    val credentialSchema: CredentialSchemaWrapper? = null,
    val credentialStatus: CredentialStatus? = null,
    val credentialSubject: CredentialSubject,
    val termsOfUse: TermsOfUse? = null,

    // [TODO #292] Keycloak sends no proof element in VerifiableCredential
    // https://github.com/tdiesler/nessus-identity/issues/292
    val proof: Proof? = null,

    // EBSI specific
    @SerialName("trust_framework")
    val trustFramework: TrustFramework? = null,

    // It is expected that the next version of this specification will add the validFrom property and
    // will deprecate the issuanceDate property in favor of a new issued property.
    @Serializable(with = TimeInstantSerializer::class)
    val issued: Instant? = null,
    @Serializable(with = TimeInstantSerializer::class)
    val validFrom: Instant? = null,
) {
    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }
}

// VCDataV11Builder ============================================================================================================================================

class VCDataV11Builder {

    var id = "${Uuid.random()}"
    var context = listOf("https://www.w3.org/2018/credentials/v1")
    var type = mutableSetOf("VerifiableCredential")
    var credentialSchema: CredentialSchemaWrapper? = null
    var credentialStatus: CredentialStatus? = null
    var credentialSubject: CredentialSubject? = null
    var issuer: Issuer? = null
    var issuanceDate: Instant? = null
    var validFrom: Instant? = null
    var validUntil: Instant? = null
    var termsOfUse: TermsOfUse? = null
    var trustFramework: TrustFramework? = null

    // v2.0
    // https://www.w3.org/standards/history/vc-data-model-2.0/
    // var validUntil: Instant? = null

    fun withContexts(contexts: List<String>): VCDataV11Builder {
        this.context = contexts
        return this
    }

    fun withCredentialSchema(schema: CredentialSchema): VCDataV11Builder {
        this.credentialSchema = CredentialSchemaWrapper.Single(schema)
        return this
    }

    fun withCredentialSchemas(schemas: List<CredentialSchema>): VCDataV11Builder {
        this.credentialSchema = CredentialSchemaWrapper.Multiple(schemas)
        return this
    }

    fun withCredentialStatus(status: CredentialStatus?): VCDataV11Builder {
        this.credentialStatus = status
        return this
    }

    fun withCredentialSubject(sub: String): VCDataV11Builder {
        this.credentialSubject = CredentialSubject(sub)
        return this
    }

    fun withId(id: String): VCDataV11Builder {
        this.id = id
        return this
    }

    fun withIssuer(id: String): VCDataV11Builder {
        this.issuer = Issuer(id)
        return this
    }

    fun withTypes(types: List<String>): VCDataV11Builder {
        this.type.addAll(types)
        return this
    }

    fun withIssuedAt(iat: Instant): VCDataV11Builder {
        this.issuanceDate = iat
        return this
    }

    fun withValidFrom(nbf: Instant): VCDataV11Builder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): VCDataV11Builder {
        this.validUntil = exp
        return this
    }

    fun build(): VCDataV11 {
        val vc = VCDataV11(
            id = id,
            context = context,
            credentialSchema = credentialSchema,
            credentialStatus = credentialStatus,
            credentialSubject = credentialSubject ?: error("No credentialSubject"),
            issuer = issuer ?: error("No issuer"),
            issuanceDate = issuanceDate ?: error("No issuanceDate"),
            expirationDate = validUntil,
            type = type.toList(),
            termsOfUse = termsOfUse,
            trustFramework = trustFramework,

            // It is expected that the next version of this specification will add the validFrom property and
            // will deprecate the issuanceDate property in favor of a new issued property.
            issued = issuanceDate,
            validFrom = validFrom,
        )
        return vc
    }
}

// CredentialSchema --------------------------------------------------------------------------------------------------------------------------------------------

@Serializable
data class CredentialSchema(
    val id: String,
    val type: String,
    /** other schema properties if any */
    val extras: Map<String, JsonElement> = emptyMap()
)

sealed class CredentialSchemaWrapper {
    data class Single(val schema: CredentialSchema) : CredentialSchemaWrapper()
    data class Multiple(val schemas: List<CredentialSchema>) : CredentialSchemaWrapper()
}

object CredentialSchemaSerializer : KSerializer<CredentialSchemaWrapper?> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("CredentialSchemas")

    @OptIn(ExperimentalSerializationApi::class)
    override fun serialize(encoder: Encoder, value: CredentialSchemaWrapper?) {
        when (value) {
            is CredentialSchemaWrapper.Single -> encoder.encodeSerializableValue(
                CredentialSchema.serializer(),
                value.schema
            )

            is CredentialSchemaWrapper.Multiple -> encoder.encodeSerializableValue(
                ListSerializer(CredentialSchema.serializer()),
                value.schemas
            )

            null -> encoder.encodeNull()
        }
    }

    override fun deserialize(decoder: Decoder): CredentialSchemaWrapper? {
        val element = (decoder as JsonDecoder).decodeJsonElement()
        return when (element) {
            is JsonObject -> CredentialSchemaWrapper.Single(
                Json.decodeFromJsonElement(CredentialSchema.serializer(), element)
            )

            is JsonArray -> CredentialSchemaWrapper.Multiple(
                Json.decodeFromJsonElement(ListSerializer(CredentialSchema.serializer()), element)
            )

            else -> null
        }
    }

}

// CredentialStatus --------------------------------------------------------------------------------------------------------------------------------------------

@Serializable
data class CredentialStatus(
    val id: String,
    val type: String,
    val statusListCredential: String?,
    val statusListIndex: String?,
    val statusPurpose: String?,
    /** extra fields if any */
    val extras: Map<String, JsonElement> = emptyMap()
)

// CredentialSubject -------------------------------------------------------------------------------------------------------------------------------------------

/**
 * https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#credential-subject
 */
@Serializable(with = CredentialSubjectSerializer::class)
data class CredentialSubject(
    val id: String? = null,
    val claims: Map<String, JsonElement> = emptyMap()
)

object CredentialSubjectSerializer : KSerializer<CredentialSubject> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("CredentialSubjectV11") {
            element<String>("id", isOptional = true)
        }

    override fun serialize(encoder: Encoder, value: CredentialSubject) {
        val jsonEncoder = encoder as? JsonEncoder
            ?: error("CredentialSubjectV11Serializer only works with JSON")

        val obj = buildJsonObject {
            value.id?.let { put("id", JsonPrimitive(it)) }
            value.claims.forEach { (k, v) -> put(k, v) }
        }
        jsonEncoder.encodeJsonElement(obj)
    }

    override fun deserialize(decoder: Decoder): CredentialSubject {
        val jsonDecoder = decoder as? JsonDecoder
            ?: error("CredentialSubjectV11Serializer only works with JSON")

        val obj = jsonDecoder.decodeJsonElement()
        require(obj is JsonObject) { "CredentialSubject must be a JSON object" }

        val id = obj["id"]?.jsonPrimitive?.contentOrNull
        val claims = obj.filterKeys { it != "id" }
        return CredentialSubject(id, claims)
    }
}

// Issuer ------------------------------------------------------------------------------------------------------------------------------------------------------

data class Issuer(
    val id: String,
    /** extra fields if any */
    val extras: Map<String, JsonElement> = emptyMap()
)

object IssuerSerializer : KSerializer<Issuer> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("Issuer") {
            element<String>("id", isOptional = true)
        }

    override fun serialize(encoder: Encoder, value: Issuer) {
        val jsonEncoder = encoder as? JsonEncoder ?: error("No a JsonEncoder")
        val json = when {
            value.extras.isEmpty() -> JsonPrimitive(value.id)
            else -> buildJsonObject {
                put("id", JsonPrimitive(value.id))
                value.extras.forEach { (k, v) -> put(k, v) }
            }
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

// Proof -------------------------------------------------------------------------------------------------------------------------------------------------------

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

// TimeInstant -------------------------------------------------------------------------------------------------------------------------------------------------

object TimeInstantSerializer : KSerializer<Instant> {
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

@Serializable
data class TermsOfUse(
    val id: String,
    val type: String
)

@Serializable
data class TrustFramework(
    val name: String,
    val type: String,
    val uri: String
)

