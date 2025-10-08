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

// VC-Data Model v1.0
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#VC_DATA
// https://www.w3.org/TR/vc-data-model-1.0/
@Serializable
data class VerifiableCredentialV10(
    val id: String? = null,
    @SerialName("@context")
    val context: List<String>? = null,
    @Serializable(with = CredentialSchemaSerializer::class)
    var credentialSchema: CredentialSchemaWrapper? = null,
    val credentialStatus: CredentialStatusV10? = null,
    val credentialSubject: CredentialSubjectV10? = null,
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
class VerifiableCredentialV10Builder {

    // v1.1
    // https://www.w3.org/standards/history/vc-data-model-1.1/
    var context: List<String>? = listOf("https://www.w3.org/2018/credentials/v1")
    var credentialSchema: CredentialSchemaWrapper? = null
    var id: String = "${Uuid.random()}"
    var credentialStatus: CredentialStatusV10? = null
    var credentialSubject: CredentialSubjectV10? = null
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

    fun withContexts(contexts: List<String>): VerifiableCredentialV10Builder {
        this.context = contexts
        return this
    }

    fun withCredentialSchema(schema: CredentialSchemaV11): VerifiableCredentialV10Builder {
        this.credentialSchema = CredentialSchemaWrapper.Single(schema)
        return this
    }

    fun withCredentialSchemas(schemas: List<CredentialSchemaV11>): VerifiableCredentialV10Builder {
        this.credentialSchema = CredentialSchemaWrapper.Multiple(schemas)
        return this
    }

    fun withCredentialStatus(status: CredentialStatusV10?): VerifiableCredentialV10Builder {
        this.credentialStatus = status
        return this
    }

    fun withCredentialSubject(sub: String): VerifiableCredentialV10Builder {
        this.credentialSubject = CredentialSubjectV10(sub)
        return this
    }

    fun withId(id: String): VerifiableCredentialV10Builder {
        this.id = id
        return this
    }

    fun withIssuer(id: String): VerifiableCredentialV10Builder {
        this.issuer = id
        return this
    }

    fun withTypes(types: List<String>): VerifiableCredentialV10Builder {
        (this.type as MutableList).addAll(types)
        return this
    }

    fun withIssuedAt(iat: Instant): VerifiableCredentialV10Builder {
        this.issuanceDate = iat
        return this
    }

    fun withValidFrom(nbf: Instant): VerifiableCredentialV10Builder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): VerifiableCredentialV10Builder {
        this.validUntil = exp
        return this
    }

    fun build(): VerifiableCredentialV10 {
        val vc = VerifiableCredentialV10(
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
data class CredentialSchemaV11(
    val id: String,
    val type: String
)

@Serializable
data class CredentialSubjectV10(
    val id: String
)

@Serializable
data class CredentialStatusV10(
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
    data class Single(val schema: CredentialSchemaV11) : CredentialSchemaWrapper()
    data class Multiple(val schemas: List<CredentialSchemaV11>) : CredentialSchemaWrapper()
}

object CredentialSchemaSerializer : KSerializer<CredentialSchemaWrapper?> {
    override val descriptor: SerialDescriptor =
        buildClassSerialDescriptor("CredentialSchemas")

    @OptIn(ExperimentalSerializationApi::class)
    override fun serialize(encoder: Encoder, value: CredentialSchemaWrapper?) {
        when (value) {
            is CredentialSchemaWrapper.Single -> encoder.encodeSerializableValue(
                CredentialSchemaV11.serializer(),
                value.schema
            )

            is CredentialSchemaWrapper.Multiple -> encoder.encodeSerializableValue(
                ListSerializer(CredentialSchemaV11.serializer()),
                value.schemas
            )

            null -> encoder.encodeNull()
        }
    }

    override fun deserialize(decoder: Decoder): CredentialSchemaWrapper? {
        val element = (decoder as JsonDecoder).decodeJsonElement()
        return when (element) {
            is JsonObject -> CredentialSchemaWrapper.Single(
                Json.decodeFromJsonElement(CredentialSchemaV11.serializer(), element)
            )

            is JsonArray -> CredentialSchemaWrapper.Multiple(
                Json.decodeFromJsonElement(ListSerializer(CredentialSchemaV11.serializer()), element)
            )

            else -> null
        }
    }

}

@Serializable
data class VerifiableCredentialV10Jwt(
    val sub: String,
    val iss: String,
    val jti: String? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    var exp: Long? = null,
    val vc: VerifiableCredentialV10,
) {
    companion object {
        fun fromEncodedJwt(encoded: String): VerifiableCredentialV10Jwt {
            val vcJwt = SignedJWT.parse(encoded)
            return Json.decodeFromString<VerifiableCredentialV10Jwt>("${vcJwt.payload}")
        }
    }
}

class VerifiableCredentialV10JwtBuilder {
    var id: String = "${Uuid.random()}"
    var issuerId: String? = null
    var subjectId: String? = null
    var issuedAt: Instant = Instant.now()
    var validFrom: Instant? = null
    var validUntil: Instant? = null
    var credential: VerifiableCredentialV10? = null

    fun withId(id: String): VerifiableCredentialV10JwtBuilder {
        this.id = id
        return this
    }

    fun withIssuerId(id: String): VerifiableCredentialV10JwtBuilder {
        this.issuerId = id
        return this
    }

    fun withSubjectId(id: String): VerifiableCredentialV10JwtBuilder {
        this.subjectId = id
        return this
    }

    fun withIssuedAt(iat: Instant): VerifiableCredentialV10JwtBuilder {
        this.issuedAt = iat
        return this
    }

    fun withValidFrom(nbf: Instant): VerifiableCredentialV10JwtBuilder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): VerifiableCredentialV10JwtBuilder {
        this.validUntil = exp
        return this
    }

    fun withCredential(vc: VerifiableCredentialV10): VerifiableCredentialV10JwtBuilder {
        this.credential = vc
        return this
    }

    fun build(): VerifiableCredentialV10Jwt {
        val issuerId = issuerId ?: throw IllegalStateException("No issuerId")
        val subjectId = subjectId ?: throw IllegalStateException("No subjectId")
        val credential = credential ?: throw IllegalStateException("No credential")
        val cred = VerifiableCredentialV10Jwt(
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
