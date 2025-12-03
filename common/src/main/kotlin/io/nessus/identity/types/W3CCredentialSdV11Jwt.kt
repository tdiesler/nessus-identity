package io.nessus.identity.types

import io.nessus.identity.utils.base64UrlDecode
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.*
import kotlin.time.Instant

@Serializable
data class W3CCredentialSdV11Jwt(
    @SerialName("_sd")
    val sdDigests: List<String>,

    @SerialName("_sd_alg")
    val sdAlgorithm: String? = null,

    val vct: String? = null,                    // Verifiable Credential type
    override val iss: String? = null,           // Issuer
    override val sub: String? = null,           // Subject
    @Serializable(with = TimeInstantSerializer::class)
    val nbf: Instant? = null,                   // Not before
    @Serializable(with = TimeInstantSerializer::class)
    val exp: Instant? = null,                   // Expiration
    override val jti: String? = null,           // Token ID
    val cnf: Confirmation? = null,              // Proof of key possession

    // [TODO] Is this an invalid property?
    val id: String? = null,                     // Credential ID
) : W3CCredentialJwt() {

    override val types get() = vct?.let { listOf(vct) } ?: listOf()

    override val vcId
        get() = jti ?: run {
            // Generate an id value as a function of all digests
            sdDigests.map { it.replace(Regex("[_-]"), "").lowercase().take(4) }
                .chunked(2).joinToString("-") { it.joinToString("") }
        }

    val disclosures = mutableListOf<Disclosure>()

    fun decodeDisclosures(encoded: String) {
        val encodedParts = encoded.split("~")
            .drop(1).filter { it.isNotBlank() }
        disclosures.addAll(
            encodedParts
                .map { part ->
                    val decoded = String(base64UrlDecode(part))
                    val arr = Json.decodeFromString<JsonArray>(decoded)
                    Disclosure(
                        decoded = decoded,
                        salt = arr[0].jsonPrimitive.content,
                        claim = arr[1].jsonPrimitive.content,
                        value = arr[2].jsonPrimitive.content
                    )
                })
    }

    fun disclosedValue(claim: String): String {
        val disc = disclosures.firstOrNull() { it.claim == claim } ?: error("Not disclosed: $claim")
        return disc.value
    }

    @Serializable
    data class Disclosure(
        @Transient
        var decoded: String? = null,
        val salt: String,
        val claim: String,
        val value: String
    )

    @Serializable
    data class Confirmation(
        val jwk: JsonWebKey? = null
    )

    @Serializable
    data class JsonWebKey(
        val kid: String? = null,
        val kty: String,
        val alg: String? = null,
        val use: String? = null,
        val crv: String? = null,
        val x: String? = null,
        val y: String? = null
    )

}

