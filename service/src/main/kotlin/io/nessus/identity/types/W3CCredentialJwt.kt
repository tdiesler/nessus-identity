package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.time.Instant
import kotlin.uuid.Uuid

@Serializable
data class W3CCredentialJwt(
    val sub: String,
    val iss: String,
    val jti: String? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    var exp: Long? = null,
    val vc: W3CCredential,
) {
    companion object {
        fun fromEncodedJwt(encoded: String): W3CCredentialJwt {
            val vcJwt = SignedJWT.parse(encoded)
            return Json.decodeFromString<W3CCredentialJwt>("${vcJwt.payload}")
        }
    }
}

class W3CCredentialJwtBuilder {
    var id: String = "${Uuid.random()}"
    var issuerId: String? = null
    var subjectId: String? = null
    var issuedAt: Instant = Instant.now()
    var validFrom: Instant? = null
    var validUntil: Instant? = null
    var credential: W3CCredential? = null

    fun withId(id: String): W3CCredentialJwtBuilder {
        this.id = id
        return this
    }

    fun withIssuerId(id: String): W3CCredentialJwtBuilder {
        this.issuerId = id
        return this
    }

    fun withSubjectId(id: String): W3CCredentialJwtBuilder {
        this.subjectId = id
        return this
    }

    fun withIssuedAt(iat: Instant): W3CCredentialJwtBuilder {
        this.issuedAt = iat
        return this
    }

    fun withValidFrom(nbf: Instant): W3CCredentialJwtBuilder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): W3CCredentialJwtBuilder {
        this.validUntil = exp
        return this
    }

    fun withCredential(vc: W3CCredential): W3CCredentialJwtBuilder {
        this.credential = vc
        return this
    }

    fun build(): W3CCredentialJwt {
        val issuerId = issuerId ?: throw IllegalStateException("No issuerId")
        val subjectId = subjectId ?: throw IllegalStateException("No subjectId")
        val credential = credential ?: throw IllegalStateException("No credential")
        val cred = W3CCredentialJwt(
            jti = id,
            iss = issuerId,
            sub = subjectId,
            iat = issuedAt.epochSecond,
            nbf = validFrom?.epochSecond,
            exp = validUntil?.epochSecond,
            vc = credential
        )
        validUntil?.also {
            cred.exp = it.epochSecond
        }
        return cred
    }
}

@Serializable
data class W3CCredential(
    val id: String? = null,
    @SerialName("@context")
    val context: List<String>? = null,
    @Serializable(with = CredentialSchemaSerializer::class)
    var credentialSchema: CredentialSchemaWrapper? = null,
    val credentialStatus: CredentialStatus? = null,
    val credentialSubject: CredentialSubject? = null,
    val issuer: String? = null,
    @Serializable(with = InstantSerializer::class)
    val issued: Instant? = null,
    @Serializable(with = InstantSerializer::class)
    val issuanceDate: Instant? = null,
    @Serializable(with = InstantSerializer::class)
    val validFrom: Instant? = null,
    @Serializable(with = InstantSerializer::class)
    var expirationDate: Instant? = null,
    val termsOfUse: TermsOfUse? = null,
    val type: List<String>? = null,
    @SerialName("trust_framework")
    val trustFramework: TrustFramework? = null,
) {
    fun toJson(): JsonObject {
        return Json.encodeToJsonElement(this).jsonObject
    }
}

// [TODO #237] Review W3C standards and their serialization
// https://github.com/tdiesler/nessus-identity/issues/237
class W3CCredentialBuilder {

    // v1.1
    // https://www.w3.org/standards/history/vc-data-model-1.1/
    var context: List<String>? = listOf("https://www.w3.org/2018/credentials/v1")
    var credentialSchema: CredentialSchemaWrapper? = null
    var id: String = "${Uuid.random()}"
    var credentialStatus: CredentialStatus? = null
    var credentialSubject: CredentialSubject? = null
    var issuer: String? = null
    var issuanceDate: Instant? = null
    var validFrom: Instant? = null
    var validUntil: Instant? = null
    var type: List<String> = mutableListOf()
    var termsOfUse: TermsOfUse? = null
    var trustFramework: TrustFramework? = null

    // v2.0
    // https://www.w3.org/standards/history/vc-data-model-2.0/
    // var validUntil: Instant? = null

    fun withContexts(contexts: List<String>): W3CCredentialBuilder {
        this.context = contexts
        return this
    }

    fun withCredentialSchema(schema: CredentialSchema): W3CCredentialBuilder {
        this.credentialSchema = CredentialSchemaWrapper.Single(schema)
        return this
    }

    fun withCredentialSchemas(schemas: List<CredentialSchema>): W3CCredentialBuilder {
        this.credentialSchema = CredentialSchemaWrapper.Multiple(schemas)
        return this
    }

    fun withCredentialStatus(status: CredentialStatus?): W3CCredentialBuilder {
        this.credentialStatus = status
        return this
    }

    fun withCredentialSubject(sub: String): W3CCredentialBuilder {
        this.credentialSubject = CredentialSubject(sub)
        return this
    }

    fun withId(id: String): W3CCredentialBuilder {
        this.id = id
        return this
    }

    fun withIssuer(id: String): W3CCredentialBuilder {
        this.issuer = id
        return this
    }

    fun withTypes(types: List<String>): W3CCredentialBuilder {
        (this.type as MutableList).addAll(types)
        return this
    }

    fun withIssuedAt(iat: Instant): W3CCredentialBuilder {
        this.issuanceDate = iat
        return this
    }

    fun withValidFrom(nbf: Instant): W3CCredentialBuilder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): W3CCredentialBuilder {
        this.validUntil = exp
        return this
    }

    fun build(): W3CCredential {
        val vc = W3CCredential(
            id = id,
            context = context,
            credentialSchema = credentialSchema,
            credentialStatus = credentialStatus,
            credentialSubject = credentialSubject,
            issuer = issuer,
            // [TODO #236] why do we need three properties for validFrom
            // https://github.com/tdiesler/nessus-identity/issues/236
            // https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
            issued = issuanceDate,
            issuanceDate = issuanceDate,
            validFrom = validFrom,
            expirationDate = validUntil,
            type = type,
            termsOfUse = termsOfUse,
            trustFramework = trustFramework,
        )
        return vc
    }
}

@Serializable
data class CredentialSchema(
    val id: String,
    val type: String
)

@Serializable
data class CredentialSubject(
    val id: String
)

@Serializable
data class CredentialStatus(
    val id: String,
    val type: String,
    val statusListCredential: String,
    val statusListIndex: String,
    val statusPurpose: String,
)

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

object InstantSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.parse(decoder.decodeString())
    }
}
