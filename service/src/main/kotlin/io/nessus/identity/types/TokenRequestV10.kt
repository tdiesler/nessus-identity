package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class TokenRequestV10 {

    abstract val grantType: GrantType
    abstract val clientId: String?
    abstract val extras: Map<String, List<String>>

    /** Each subclass must expose its own field map for form encoding */
    abstract fun specificParameters(): Map<String, List<String>>

    fun toHttpParameters(): Map<String, List<String>> {
        return buildMap {
            put("grant_type", listOf(grantType.value))
            clientId?.let { put("client_id", listOf(it)) }
            putAll(specificParameters())
            putAll(extras)
        }
    }

    companion object {
        private val knownKeys = setOf(
            "grant_type", "client_id", "redirect_uri", "code", "pre-authorized_code", "tx_code", "code_verifier"
        )

        fun fromHttpParameters(parameters: Map<String, List<String>>): TokenRequestV10 {
            val grantType = parameters["grant_type"]!!.first().let { GrantType.fromValue(it)!! }
            val extras = parameters.filterKeys { !knownKeys.contains(it) }

            return when (grantType) {
                GrantType.AUTHORIZATION_CODE -> AuthorizationCode(
                    clientId = parameters["client_id"]?.firstOrNull()
                        ?: throw IllegalArgumentException("Missing 'client_id' for Authorization Code flow."),
                    code = parameters["code"]?.firstOrNull()
                        ?: throw IllegalArgumentException("Missing 'code' for Authorization Code flow."),
                    redirectUri = parameters["redirect_uri"]?.firstOrNull(),
                    codeVerifier = parameters["code_verifier"]?.firstOrNull(),
                    extras = extras
                )

                GrantType.PRE_AUTHORIZED_CODE -> PreAuthorizedCode(
                    preAuthorizedCode = parameters["pre-authorized_code"]?.firstOrNull()
                        ?: throw IllegalArgumentException("Missing 'pre-authorized_code' for Pre-Authorized flow."),
                    txCode = parameters["tx_code"]?.firstOrNull(),
                    userPin = parameters["user_pin"]?.firstOrNull(),
                    clientId = parameters["client_id"]?.firstOrNull(),
                    extras = extras
                )
            }
        }
    }

    @Serializable
    enum class GrantType(val value: String) {

        @SerialName("authorization_code")
        AUTHORIZATION_CODE("authorization_code"),

        @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        PRE_AUTHORIZED_CODE("urn:ietf:params:oauth:grant-type:pre-authorized_code");

        companion object {
            fun fromValue(value: String): GrantType? =
                entries.find { it.value == value }
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
        override val extras: Map<String, List<String>> = emptyMap()
    ) : TokenRequestV10() {
        override val grantType = GrantType.AUTHORIZATION_CODE

        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("code", listOf(code))
            redirectUri?.let { put("redirect_uri", listOf(it)) }
            codeVerifier?.let { put("code_verifier", listOf(it)) }
        }
    }

    @Serializable
    data class PreAuthorizedCode(
        @SerialName("pre-authorized_code")
        val preAuthorizedCode: String,
        @SerialName("tx_code")
        val txCode: String? = null,
        @SerialName("user_pin")
        val userPin: String? = null,
        @SerialName("client_id")
        override val clientId: String? = null,
        override val extras: Map<String, List<String>> = emptyMap()
    ) : TokenRequestV10() {
        override val grantType = GrantType.PRE_AUTHORIZED_CODE

        override fun specificParameters(): Map<String, List<String>> = buildMap {
            put("pre-authorized_code", listOf(preAuthorizedCode))
            txCode?.let { put("tx_code", listOf(it)) }
            userPin?.let { put("user_pin", listOf(it)) }
        }
    }
}
