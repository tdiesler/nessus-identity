package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.VCDataV11
import kotlin.time.Clock

// VerifierService =====================================================================================================

class VerifierServiceEbsi32 : VerifierService {

    val log = KotlinLogging.logger {}

    override fun validateVerifiableCredential(vc: VCDataV11, vcp: CredentialParameters?) {

        val id = vc.id ?: throw IllegalArgumentException("No credential id: $vc")

        vc.credentialStatus?.also { status ->
            if (status.statusPurpose == "revocation")
                throw VerificationException(id, "Credential '$id' is revoked")
        }

        val now = Clock.System.now()
        if (vc.expirationDate != null && vc.expirationDate < now)
            throw VerificationException(id, "Credential '$id' is expired")

        if (vc.validFrom != null && vc.validFrom > now)
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