package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.*
import java.util.*
import kotlin.text.Charsets.UTF_8
import kotlin.time.Instant

@Serializable
data class VCDataSdV11Jwt(
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
    val id: String? = null,                     // Credential ID
    val cnf: Confirmation? = null,              // Proof of key possession
) : VCDataJwt() {

    override val types get() = vct?.let { listOf(vct) } ?: listOf()

    override val vcId
        get() = jti ?: run {
            // Generate an id value as a function of all digests
            sdDigests.map { it.replace(Regex("[_-]"), "").lowercase().take(4) }
                .chunked(2).joinToString("-") { it.joinToString("") }
        }

    val disclosures= mutableListOf<Disclosure>()

    fun disclosureToDigests(): List<Pair<Disclosure, String>> = run {
        return disclosures.map {
            val json = Json // default config; used only to quote strings
            val s = json.encodeToString(String.serializer(), it.salt)
            val c = json.encodeToString(String.serializer(), it.claim)
            val v = json.encodeToString(String.serializer(), it.value)
            val payload = "[${s}, ${c}, ${v}]".toByteArray(UTF_8)   // note the spaces after commas
            val digest =  Base64.getUrlEncoder().withoutPadding().encodeToString(payload)
            Pair(it, digest)
        }
    }

    fun decodeDisclosures(encoded: String): List<Disclosure> {
        val decoder = Base64.getUrlDecoder()
        val encodedParts = encoded.split("~")
            .drop(1).filter { it.isNotBlank() }
        disclosures.addAll(encodedParts
            .map { part ->
                val arr = Json.decodeFromString<JsonArray>(decoder.decode(part).decodeToString())
                Disclosure(
                    salt = arr[0].jsonPrimitive.content,
                    claim = arr[1].jsonPrimitive.content,
                    value = arr[2].jsonPrimitive.content
                )
            })
        require(encodedParts == disclosureToDigests().map { it.second })
        return disclosures
    }

    @Serializable
    data class Disclosure(
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

