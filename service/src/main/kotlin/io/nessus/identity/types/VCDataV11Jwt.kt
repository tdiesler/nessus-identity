package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.Uuid

// VCDataV11Jwt ================================================================================================================================================

@Serializable
data class VCDataV11Jwt(
    override val iss: String? = null,
    override val sub: String? = null,
    override val jti: String? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    var exp: Long? = null,
    val vc: VCDataV11,
): VCDataJwt() {

    override val vcId get() = jti ?: vc.id ?: error("No credential id")

    companion object {
        fun fromEncoded(encoded: String): VCDataV11Jwt {
            val vcJwt = SignedJWT.parse(encoded)
            return Json.decodeFromString<VCDataV11Jwt>("${vcJwt.payload}")
        }
    }
}

class VCDataV11JwtBuilder {
    var id: String = "${Uuid.random()}"
    var issuerId: String? = null
    var subjectId: String? = null
    var issuedAt: Instant = Clock.System.now()
    var validFrom: Instant? = null
    var validUntil: Instant? = null
    var credential: VCDataV11? = null

    fun withId(id: String): VCDataV11JwtBuilder {
        this.id = id
        return this
    }

    fun withIssuerId(id: String): VCDataV11JwtBuilder {
        this.issuerId = id
        return this
    }

    fun withSubjectId(id: String): VCDataV11JwtBuilder {
        this.subjectId = id
        return this
    }

    fun withIssuedAt(iat: Instant): VCDataV11JwtBuilder {
        this.issuedAt = iat
        return this
    }

    fun withValidFrom(nbf: Instant): VCDataV11JwtBuilder {
        this.validFrom = nbf
        return this
    }

    fun withValidUntil(exp: Instant): VCDataV11JwtBuilder {
        this.validUntil = exp
        return this
    }

    fun withCredential(vc: VCDataV11): VCDataV11JwtBuilder {
        this.credential = vc
        return this
    }

    fun build(): VCDataV11Jwt {
        val issuerId = issuerId ?: throw IllegalStateException("No issuerId")
        val subjectId = subjectId ?: throw IllegalStateException("No subjectId")
        val credential = credential ?: throw IllegalStateException("No credential")
        val cred = VCDataV11Jwt(
            jti = id,
            iss = issuerId,
            sub = subjectId,
            iat = issuedAt.epochSeconds,
            nbf = validFrom?.epochSeconds,
            exp = validUntil?.epochSeconds,
            vc = credential
        )
        validUntil?.also {
            cred.exp = it.epochSeconds
        }
        return cred
    }
}
