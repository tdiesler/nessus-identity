package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonPrimitive
import java.util.*
import kotlin.time.Instant
import kotlin.uuid.Uuid

@Serializable
data class VCDataSdV11Jwt(
    @SerialName("_sd")
    val sdDigests: List<String>? = null,

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
): VCDataJwt() {

    override val types get() = vct?.let { listOf(vct) } ?: listOf()

    // [TODO #301] Keycloak issues oid4vc_natural_person with invalid id value
    // https://github.com/tdiesler/nessus-identity/issues/301
    override val vcId get() = jti ?: id ?: run { "DUMMY-${Uuid.random()}" }

    @Transient
    val disclosures = mutableListOf<Disclosure>()

    fun decodeDisclosures(encoded: String): List<Disclosure> {
        val decoder = Base64.getUrlDecoder()
        val encodedParts = encoded.substringAfter("~").split("~")
        val res = encodedParts
            .filter { it.isNotBlank() }
            .map { part ->
                val arr = Json.decodeFromString<JsonArray>(decoder.decode(part).decodeToString())
                Disclosure(
                    salt = arr[0].jsonPrimitive.content,
                    claim = arr[1].jsonPrimitive.content,
                    value = arr[2].jsonPrimitive.content
                )
            }
        disclosures.addAll(res)
        return res
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

