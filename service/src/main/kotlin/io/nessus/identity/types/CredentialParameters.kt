package io.nessus.identity.types

import java.time.Instant
import kotlin.uuid.ExperimentalUuidApi

data class CredentialParameters(
    val id: String?,
    val iss: String?,
    val sub: String?,
    val iat: Instant?,
    val exp: Instant?,
    val types: List<String>,
)

@OptIn(ExperimentalUuidApi::class)
class CredentialParametersBuilder() {

    var id: String? = null
    var iat = Instant.now()
    var exp = iat.plusSeconds(86400) // 24h
    var iss: String? = null
    var sub: String? = null
    var types = listOf<String>()

    fun withId(id: String): CredentialParametersBuilder {
        this.id = id
        return this
    }

    fun withExpire(exp: Instant): CredentialParametersBuilder {
        this.exp = exp
        return this
    }

    fun withIssuer(iss: String): CredentialParametersBuilder {
        this.iss = iss
        return this
    }

    fun withIssuedAt(iat: Instant): CredentialParametersBuilder {
        this.iat = iat
        return this
    }

    fun withSubject(sub: String): CredentialParametersBuilder {
        this.sub = sub
        return this
    }

    fun withTypes(types: List<String>): CredentialParametersBuilder {
        this.types = types
        return this
    }

    fun build(): CredentialParameters {
        return CredentialParameters(id, iss, sub, iat, exp, types)
    }
}