package io.nessus.identity.types

import id.walt.oid4vc.data.dif.PresentationDefinition
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

typealias AuthorizationDetailsDraft11 = id.walt.oid4vc.data.AuthorizationDetails
typealias ClientMetadataDraft11 = id.walt.oid4vc.data.OpenIDClientMetadata

@Serializable
data class AuthorizationRequestDraft11(
    @SerialName("client_id")
    override val clientId: String,

    @SerialName("redirect_uri")
    override val redirectUri: String? = null,

    @SerialName("response_type")
    override val responseType: String? = null,

    @SerialName("response_mode")
    override val responseMode: String? = null,

    @SerialName("request")
    override val request: String? = null,

    @SerialName("request_uri")
    override val requestUri: String? = null,

    @SerialName("response_uri")
    override val responseUri: String? = null,

    @SerialName("nonce")
    override val nonce: String? = null,

    @SerialName("scope")
    override val scope: String? = null,

    @SerialName("state")
    override val state: String? = null,

    @SerialName("code_challenge")
    override val codeChallenge: String? = null,

    @SerialName("code_challenge_method")
    override val codeChallengeMethod: String? = null,

    // Uncommon attributes --------------------------------------

    @SerialName("authorization_details")
    val authorizationDetails: List<AuthorizationDetailsDraft11>? = null,

    @SerialName("client_metadata")
    val clientMetadata: ClientMetadataDraft11? = null,

    @SerialName("client_metadata_uri")
    val clientMetadataUri: String? = null,

    @SerialName("issuer_state")
    val issuerState: String? = null,

    @SerialName("presentation_definition")
    val presentationDefinition: PresentationDefinition? = null,

    @SerialName("presentation_definition_uri")
    val presentationDefinitionUri: String? = null,

//    val walletIssuer: String? = null,
//    val userHint: String? = null,
//    val clientIdScheme: ClientIdScheme? = null,
//    val claims: JsonObject? = null,
//    val idTokenHint: String? = null,
//    val requireSignedRequestObject: Boolean? = null, //required by ISO 18013-7 specification
//    val customParameters: Map<String, List<String>> = mapOf()

): AuthorizationRequest() {

    override fun toRequestParameters(): Map<String, List<String>> {
        return buildMap {
            putAll(super.toRequestParameters())
            authorizationDetails?.also {
                val json = Json.encodeToString(it)
                put("authorization_details", listOf(json))
            }
            clientMetadata?.also {
                val json = Json.encodeToString(it)
                put("client_metadata", listOf(json))
            }
            clientMetadataUri?.also { put("client_metadata_uri", listOf(it)) }
            issuerState?.also { put("issuer_state", listOf(it)) }
            presentationDefinition?.also {
                val json = Json.encodeToString(it)
                put("presentation_definition", listOf(json))
            }
            presentationDefinitionUri?.also { put("presentation_definition_uri", listOf(it)) }
        }
    }

    override fun toJson() = Json.encodeToString(this)
    override fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true }
        fun fromJson(json: String) = jsonInst.decodeFromString<AuthorizationRequestDraft11>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<AuthorizationRequestDraft11>(json)

        fun fromHttpParameters(params: Map<String, String>): AuthorizationRequestDraft11 {
            return AuthorizationRequestDraft11(
                clientId = params["client_id"] ?: error("No client_id"),
                redirectUri = params["redirect_uri"],
                responseType = params["response_type"] ?: error("No response_type"),
                responseMode = params["response_mode"],
                request = params["request"],
                requestUri = params["request_uri"],
                responseUri = params["response_uri"],
                scope = params["scope"],
                nonce = params["nonce"],
                state = params["state"],
                codeChallenge = params["code_challenge"],
                codeChallengeMethod = params["code_challenge_method"],
                authorizationDetails = params["authorization_details"]?.let {
                    Json.decodeFromString<List<AuthorizationDetailsDraft11>>(it)
                },
                clientMetadata = params["client_metadata"]?.let {
                    Json.decodeFromString<ClientMetadataDraft11>(it)
                },
                clientMetadataUri = params["client_metadata_uri"],
                issuerState = params["issuer_state"],
                presentationDefinition = params["presentation_definition"]?.let {
                    Json.decodeFromString<PresentationDefinition>(it)
                },
                presentationDefinitionUri = params["presentation_definition_uri"],
            )
        }
    }
}