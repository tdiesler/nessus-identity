package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.W3CCredential
import java.time.Instant

// VerifierService =====================================================================================================

class DefaultVerifierService : VerifierService {

    val log = KotlinLogging.logger {}

    override fun validateVerifiableCredential(vc: W3CCredential, vcp: CredentialParameters?) {

        val id = vc.id ?: throw IllegalArgumentException("No credential id: $vc")

        vc.credentialStatus?.also { status ->
            if (status.statusPurpose == "revocation")
                throw VerificationException(id, "Credential '$id' is revoked")
        }

        val now = Instant.now()
        if (vc.expirationDate?.isBefore(now) ?: false)
            throw VerificationException(id, "Credential '$id' is expired")

        if (vc.validFrom?.isAfter(now) ?: false)
            throw VerificationException(id, "Credential '$id' is not yet valid")

        if (vcp?.sub != null) {
            val vcJson = vc.toJson()
            val vcSubject = CredentialMatcher.pathValues("$vcJson", "$.credentialSubject.id").first()
            if (vcSubject != vcp.sub)
                throw IllegalStateException("Unexpected subject id: $vcSubject")
        }

        if (vcp?.types?.isNotEmpty() ?: false) {
            val vcJson = vc.toJson()
            val vcTypes = CredentialMatcher.pathValues("$vcJson", "$.type")
            if (!vcTypes.containsAll(vcp.types))
                throw IllegalStateException("Unexpected credential types: $vcTypes")
        }
    }
}