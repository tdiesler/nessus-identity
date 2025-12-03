package io.nessus.identity.types

import kotlin.time.Instant

class CredentialParameters() {

    var id: String? = null
    var iss: String? = null
    var sub: String? = null
    var iat: Instant? = null
    var nbf: Instant? = null
    var exp: Instant? = null
    var types = listOf<String>()
    var status: CredentialStatus? = null

    fun withId(id: String): CredentialParameters {
        this.id = id
        return this
    }

    fun withIssuer(iss: String): CredentialParameters {
        this.iss = iss
        return this
    }

    fun withIssuedAt(iat: Instant): CredentialParameters {
        this.iat = iat
        return this
    }

    fun withStatus(status: CredentialStatus): CredentialParameters {
        this.status = status
        return this
    }

    fun withSubject(sub: String): CredentialParameters {
        this.sub = sub
        return this
    }

    fun withTypes(types: List<String>): CredentialParameters {
        this.types = types
        return this
    }

    fun withValidFrom(nbf: Instant): CredentialParameters {
        this.nbf = nbf
        return this
    }

    fun withValidUntil(exp: Instant): CredentialParameters {
        this.exp = exp
        return this
    }
}
