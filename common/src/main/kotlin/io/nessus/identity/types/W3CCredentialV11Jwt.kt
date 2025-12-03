package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.Uuid

// W3CCredentialV11Jwt =================================================================================================

@Serializable
data class W3CCredentialV11Jwt(
    override val iss: String? = null,
    override val sub: String? = null,
    override val jti: String? = null,
    val iat: Long? = null,
    val nbf: Long? = null,
    var exp: Long? = null,
    val vc: W3CCredentialV11,
): W3CCredentialJwt() {

    override val vcId get() = jti ?: vc.id ?: error("No credential id")
    override val types get() = vc.type

    companion object {
        fun fromEncoded(encoded: String): W3CCredentialV11Jwt {
            val credJwt = SignedJWT.parse(encoded)
            return Json.decodeFromString<W3CCredentialV11Jwt>("${credJwt.payload}")
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
    var credential: W3CCredentialV11? = null

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

    fun withCredential(vc: W3CCredentialV11): VCDataV11JwtBuilder {
        this.credential = vc
        return this
    }

    fun build(): W3CCredentialV11Jwt {
        val issuerId = issuerId ?: throw IllegalStateException("No issuerId")
        val subjectId = subjectId ?: throw IllegalStateException("No subjectId")
        val credential = credential ?: throw IllegalStateException("No credential")
        val cred = W3CCredentialV11Jwt(
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
