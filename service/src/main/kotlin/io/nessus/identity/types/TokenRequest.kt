package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class GrantType(val value: String) {

    @SerialName("authorization_code")
    AUTHORIZATION_CODE("authorization_code"),

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code"),

    @SerialName("client_credentials")
    CLIENT_CREDENTIALS("client_credentials"),

    @SerialName("password")
    DIRECT_ACCESS("password"),

    @SerialName("refresh_token")
    REFRESH_TOKEN("refresh_token");

    companion object {
        fun fromValue(value: String): GrantType? =
            entries.find { it.value == value }
    }
}

@Serializable
sealed class TokenRequest {

    abstract val grantType: GrantType
    abstract val clientId: String?

    /** Each subclass must expose its own field map for form encoding */
    abstract fun specificParameters(): Map<String, List<String>>

    fun getParameters(): Map<String, List<String>> {
        return buildMap {
            put("grant_type", listOf(grantType.value))
            clientId?.also { put("client_id", listOf(it)) }
            putAll(specificParameters())
        }
    }

    companion object {
        private val knownKeys = setOf(
            "client_id", 
            "client_secret",
            "code",
            "code_verifier",
            "grant_type",
            "pre-authorized_code",
            "redirect_uri", 
            "tx_code"
        )

        fun fromHttpParameters(parameters: Map<String, List<String>>): TokenRequest {
            val grantType = parameters["grant_type"]!!.first().let { GrantType.fromValue(it)!! }

            return when (grantType) {
                GrantType.AUTHORIZATION_CODE -> AuthorizationCode(
                    clientId = parameters["client_id"]?.firstOrNull()
                        ?: error("Missing 'client_id' for Authorization Code flow."),
                    code = parameters["code"]?.firstOrNull()
                        ?: error("Missing 'code' for Authorization Code flow."),
                    redirectUri = parameters["redirect_uri"]?.firstOrNull(),
                    codeVerifier = parameters["code_verifier"]?.firstOrNull(),
                )
                GrantType.PRE_AUTHORIZED_CODE -> PreAuthorizedCode(
                    preAuthorizedCode = parameters["pre-authorized_code"]?.firstOrNull()
                        ?: error("Missing 'pre-authorized_code' for Pre-Authorized flow."),
                    txCode = parameters["tx_code"]?.firstOrNull(),
                    userPin = parameters["user_pin"]?.firstOrNull(),
                    clientId = parameters["client_id"]?.firstOrNull(),
                )
                else -> error("Unsupported grant_type: $grantType")
            }
        }
    }

    @Serializable
    data class AuthorizationCode(
        @SerialName("client_id")
        override val clientId: String,
        @SerialName("redirect_uri")
        val redirectUri: String? = null,
        val code: String,
        @SerialName("code_verifier")
        val codeVerifier: String? = null,
    ) : TokenRequest() {
        override val grantType = GrantType.AUTHORIZATION_CODE

        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("code", listOf(code))
            redirectUri?.let { put("redirect_uri", listOf(it)) }
            codeVerifier?.let { put("code_verifier", listOf(it)) }
        }
    }

    @Serializable
    data class PreAuthorizedCode(
        @SerialName("client_id")
        override val clientId: String? = null,
        @SerialName("pre-authorized_code")
        val preAuthorizedCode: String,
        @SerialName("tx_code")
        val txCode: String? = null,
        @SerialName("user_pin")
        val userPin: String? = null,
    ) : TokenRequest() {
        override val grantType = GrantType.PRE_AUTHORIZED_CODE
        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("pre-authorized_code", listOf(preAuthorizedCode))
            txCode?.let { put("tx_code", listOf(it)) }
            userPin?.let { put("user_pin", listOf(it)) }
        }
    }

    @Serializable
    data class ClientCredentials(
        @SerialName("client_id")
        override val clientId: String,
        @SerialName("client_secret")
        val clientSecret: String,
        @SerialName("scopes")
        val scopes: List<String>? = null,
    ) : TokenRequest() {
        override val grantType = GrantType.CLIENT_CREDENTIALS
        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("client_secret", listOf(clientSecret))
            scopes?.also { put("scope", listOf(scopes.joinToString(" "))) }
        }
    }

    @Serializable
    data class DirectAccess(
        @SerialName("client_id")
        override val clientId: String,
        @SerialName("username")
        val username: String,
        @SerialName("password")
        val password: String,
        @SerialName("scopes")
        val scopes: List<String>? = null,
    ) : TokenRequest() {
        override val grantType = GrantType.DIRECT_ACCESS
        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("username", listOf(username))
            put("password", listOf(password))
            scopes?.also { put("scope", listOf(scopes.joinToString(" "))) }
        }
    }
}
