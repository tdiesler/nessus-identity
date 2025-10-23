package io.nessus.identity.types

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.service.http
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = CredentialOfferSerializer::class)
sealed class CredentialOffer {

    abstract val credentialConfigurationIds: List<String>
    abstract val credentialIssuer: String
    abstract val grants: Grants?

    val filteredConfigurationIds get() = credentialConfigurationIds
        .filter { it != "VerifiableAttestation" }
        .filter { it != "VerifiableCredential" }

    @Transient
    private lateinit var issuerMetadata: IssuerMetadata

    fun getAuthorizationCodeGrant() : AuthorizationCodeGrant? {
        return grants?.authorizationCode
    }

    fun getPreAuthorizedCodeGrant() : PreAuthorizedCodeGrant? {
        return grants?.preAuthorizedCode
    }

    @Suppress("UNCHECKED_CAST")
    suspend fun <IMType: IssuerMetadata> resolveIssuerMetadata(): IMType {
        if (!::issuerMetadata.isInitialized) {
            val issuerMetadataUrl = "$credentialIssuer/.well-known/openid-credential-issuer"
            issuerMetadata = http.get(issuerMetadataUrl).body<IssuerMetadata>()
        }
        return issuerMetadata as IMType
    }

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<CredentialOffer>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<CredentialOffer>(json)
    }
}

object CredentialOfferSerializer : JsonContentPolymorphicSerializer<CredentialOffer>(CredentialOffer::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialOffer> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("credentials") -> CredentialOfferDraft11.serializer()
            jsonObj.containsKey("credential_configuration_ids") -> CredentialOfferV10.serializer()
            else -> throw SerializationException("Unknown CredentialEntry type: $element")
        }
    }
}