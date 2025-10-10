package io.nessus.identity.types

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-offer-endpoint
*/
@Serializable
data class CredentialOfferDraft11(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credentials")
    val credentials: List<CredentialEntry>,

    override val grants: Grants? = null
) : CredentialOffer() {

    override fun getTypes(): List<String> {
        return when (val entry = credentials.first()) {
            is CredentialObject -> entry.types
            is CredentialReference -> listOf(entry.reference)
        }
    }

    fun toWaltIdCredentialOffer(): id.walt.oid4vc.data.CredentialOffer {
        val jsonObj = Json.encodeToJsonElement(this).jsonObject
        return id.walt.oid4vc.data.CredentialOffer.fromJSON(jsonObj)
    }
}

@Serializable(with = CredentialEntrySerializer::class)
sealed class CredentialEntry

@Serializable
data class CredentialObject(
    @SerialName("format")
    val format: String,
    @SerialName("types")
    val types: List<String>,
    @SerialName("id")
    val id: String? = null,
    @SerialName("credentialSubject")
    val credentialSubject: JsonElement? = null,
    @SerialName("trust_framework")
    val trustFramework: TrustFramework? = null,
) : CredentialEntry()

@Serializable
data class CredentialReference(
    val reference: String
) : CredentialEntry()

object CredentialEntrySerializer : JsonContentPolymorphicSerializer<CredentialEntry>(CredentialEntry::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialEntry> {
        return when(element) {
            is JsonObject -> CredentialObject.serializer()
            is JsonPrimitive -> CredentialReference.serializer()
            else -> throw SerializationException("Unknown CredentialEntry type: $element")
        }
    }
}