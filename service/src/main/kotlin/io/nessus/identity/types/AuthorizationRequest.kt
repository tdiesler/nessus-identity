package io.nessus.identity.types

import io.nessus.identity.service.urlEncode
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

@Serializable(with = AuthorizationRequestSerializer::class)
sealed class AuthorizationRequest {
    abstract val clientId: String
    abstract val redirectUri: String?
    abstract val responseType: String?
    abstract val responseMode: String?
    abstract val request: String?
    abstract val requestUri: String?
    abstract val responseUri: String?
    abstract val scope: String?
    abstract val nonce: String?
    abstract val state: String?
    abstract val codeChallenge: String?
    abstract val codeChallengeMethod: String?

    abstract fun toJson(): String
    abstract fun toJsonObj(): JsonObject

    open fun toRequestParameters(): Map<String, List<String>> {
        return buildMap {
            put("client_id", listOf(clientId))
            redirectUri?.also { put("redirect_uri", listOf(it)) }
            responseType?.also { put("response_type", listOf(it)) }
            responseMode?.also { put("response_mode", listOf(it)) }
            request?.also { put("request", listOf(it)) }
            requestUri?.also { put("request_uri", listOf(it)) }
            responseUri?.also { put("response_uri", listOf(it)) }
            scope?.also { put("scope", listOf(it)) }
            nonce?.also { put("nonce", listOf(it)) }
            state?.also { put("state", listOf(it)) }
            codeChallenge?.also { put("code_challenge", listOf(it)) }
            codeChallengeMethod?.also { put("code_challenge_method", listOf(it)) }
        }
    }

    fun toRequestUrl(authEndpointUri: String): String {
        val params = toRequestParameters()
            .map { (k, vals) -> vals.joinToString("&") { v -> "$k=${urlEncode(v)}" }}
            .joinToString( "&" )
        return "$authEndpointUri?$params"
    }
}

object AuthorizationRequestSerializer :
    JsonContentPolymorphicSerializer<AuthorizationRequest>(AuthorizationRequest::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<AuthorizationRequest> {
        val jsonObj = element.jsonObject

        // AuthorizationDetails discrimination
        //
        if (jsonObj.containsKey("authorization_details")) {
            val ads = jsonObj.getValue("authorization_details").jsonObject
            val isAuthDetailsDraft11 = (ads.containsKey("vct")
                    || ads.containsKey("types")
                    || ads.containsKey("credential_definition"))
            val isAuthDetailsV0 = (ads.containsKey("credential_configuration_id")
                    || ads.containsKey("credential_identifiers")
                    || ads.containsKey("credential_type"))
            if (isAuthDetailsDraft11 && isAuthDetailsV0)
                throw SerializationException("Ambiguous AuthorizationDetails: $element")
            return when {
                isAuthDetailsV0 -> AuthorizationRequestV0.serializer()
                isAuthDetailsDraft11 -> AuthorizationRequestDraft11.serializer()
                else -> throw SerializationException("Unknown AuthorizationDetails: $element")
            }
        }

        // AuthorizationRequest discrimination
        //
        val isAuthorizationRequestDraft11 = (jsonObj.containsKey("presentation_definition")
                || jsonObj.containsKey("presentation_definition_uri")
                || jsonObj.containsKey("issuer_state"))
        val isAuthorizationRequestV0 = (jsonObj.containsKey("dcql_query")
                || jsonObj.containsKey("request_uri_method")
                || jsonObj.containsKey("transaction_data"))
        if (isAuthorizationRequestDraft11 && isAuthorizationRequestV0)
            throw SerializationException("Ambiguous AuthorizationRequest: $element")
        return when {
            isAuthorizationRequestV0 -> AuthorizationRequestV0.serializer()
            isAuthorizationRequestDraft11 -> AuthorizationRequestDraft11.serializer()
            else -> throw SerializationException("Unknown AuthorizationRequest: $element")
        }
    }
}
