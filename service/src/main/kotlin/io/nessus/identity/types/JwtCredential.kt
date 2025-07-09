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
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject
import java.time.Instant
import kotlin.uuid.ExperimentalUuidApi

@OptIn(ExperimentalUuidApi::class)
class JwtCredentialBuilder(val id: String, val issuerId: String, val subjectId: String) {
    var issuedAt: Instant = Instant.now()
    var expiration: Instant? = null
    var credentialSchema: CredentialSchemaWrapper? = null
    val types: List<String> = mutableListOf()

    fun withExpiration(exp: Instant): JwtCredentialBuilder {
        expiration = exp
        return this
    }

    fun withCredentialSchema(schema: CredentialSchema): JwtCredentialBuilder {
        this.credentialSchema = CredentialSchemaWrapper.Single(schema)
        return this
    }

    fun withCredentialSchemas(schemas: List<CredentialSchema>): JwtCredentialBuilder {
        this.credentialSchema = CredentialSchemaWrapper.Multiple(schemas)
        return this
    }

    fun withTypes(types: List<String>): JwtCredentialBuilder {
        (this.types as MutableList<String>).addAll(types)
        return this
    }

    fun build(): JwtCredential {
        val cred = JwtCredential(
            jti = id,
            iss = issuerId,
            sub = subjectId,
            iat = issuedAt.epochSecond,
            nbf = issuedAt.epochSecond,
            vc = W3CCredential(
                context = listOf("https://www.w3.org/2018/credentials/v1"),
                id = id,
                credentialSubject = CredentialSubject(id = subjectId),
                credentialSchema = credentialSchema ?: throw IllegalStateException("No CredentialSchema"),
                issuer = issuerId,
                issued = issuedAt,
                issuanceDate = issuedAt,
                validFrom = issuedAt,
                type = types
            )
        )
        expiration?.also {
            cred.exp = it.epochSecond
            cred.vc.expirationDate = it
        }
        return cred
    }

}

@Serializable
data class JwtCredential(
    val sub: String,
    val jti: String,
    val iss: String,
    val iat: Long,
    val nbf: Long,
    var exp: Long? = null,
    val vc: W3CCredential,
)

@Serializable
data class W3CCredential(
    @SerialName("@context")
    val context: List<String>,
    @Serializable(with = CredentialSchemaSerializer::class)
    val credentialSchema: CredentialSchemaWrapper? = null,
    val credentialSubject: CredentialSubject,
    val id: String,
    val issuer: String,
    @Serializable(with = InstantSerializer::class)
    val issued: Instant,
    @Serializable(with = InstantSerializer::class)
    val issuanceDate: Instant,
    @Serializable(with = InstantSerializer::class)
    val validFrom: Instant,
    @Serializable(with = InstantSerializer::class)
    var expirationDate: Instant? = null,
    val type: List<String>,
    val termsOfUse: TermsOfUse? = null
)

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
data class TermsOfUse(
    val id: String,
    val type: String
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
