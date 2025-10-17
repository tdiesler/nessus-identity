package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlin.time.Instant

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
    val vc: Map<String, JsonElement>? = null    // Optional embedded VC claims
): VCDataJwt() {

    override val vcId get() = jti ?: id ?: error("No credential id")
    override val types get() = vct?.let { listOf(vct) } ?: listOf()

    companion object {
        fun fromEncoded(encoded: String): VCDataSdV11Jwt {
            val vcJwt = SignedJWT.parse(encoded)
            return Json.decodeFromString<VCDataSdV11Jwt>("${vcJwt.payload}")
        }
    }
}

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
