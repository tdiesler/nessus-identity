package io.nessus.identity.types

import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.utils.http
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = CredentialOfferSerializer::class)
sealed class CredentialOffer {

    abstract val credentialConfigurationIds: List<String>
    abstract val credentialIssuer: String
    abstract val grants: Grants?

    val filteredConfigurationIds
        get() = credentialConfigurationIds.filter { it !in listOf("VerifiableAttestation", "VerifiableCredential") }

    val isPreAuthorized
        get() = grants?.preAuthorizedCode?.preAuthorizedCode != null
    val isUserPinRequired
        get() = grants?.preAuthorizedCode?.userPinRequired == true

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

@Serializable
data class Grants(
    @SerialName("authorization_code")
    val authorizationCode: AuthorizationCodeGrant? = null,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: PreAuthorizedCodeGrant? = null
)

@Serializable
data class AuthorizationCodeGrant(
    @SerialName("issuer_state")
    val issuerState: String? = null,

    @SerialName("authorization_server")
    val authorizationServer: String? = null,

    // [TODO #275] How to know the client_id for the Authorization Request
    // https://github.com/tdiesler/nessus-identity/issues/275
    @SerialName("client_id")
    val clientId: String? = null,
)

@Serializable
data class PreAuthorizedCodeGrant(
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String,
    @SerialName("tx_code")
    val txCode: TransactionCode? = null,
    // [TODO] Remove legacy user_pin_required, its been replaced by tx_code
    @SerialName("user_pin_required")
    val userPinRequired: Boolean? = null,
)

@Serializable
data class TransactionCode(
    val length: Int? = null,
    @SerialName("input_mode")
    val inputMode: String? = null,
    val description: String? = null
)

object CredentialOfferSerializer : JsonContentPolymorphicSerializer<CredentialOffer>(CredentialOffer::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialOffer> {
        val jsonObj = element.jsonObject
        return when {
            jsonObj.containsKey("credentials") -> CredentialOfferDraft11.serializer()
            jsonObj.containsKey("credential_configuration_ids") -> CredentialOfferV0.serializer()
            else -> throw SerializationException("Unknown CredentialOffer type: $element")
        }
    }
}
