package io.nessus.identity.types

import kotlin.time.Clock

object W3CCredentialValidator {

    fun validateVerifiableCredential(vpcJwt: W3CCredentialV11Jwt, vcp: CredentialParameters? = null) {

        val vc = vpcJwt.vc
        val id = vpcJwt.vcId

        vc.credentialStatus?.also { status ->
            if (status.statusPurpose == "revocation")
                throw VerificationException(id, "Credential '$id' is revoked")
        }

        val now = Clock.System.now()
        if (vc.expirationDate != null && vc.expirationDate!! < now)
            throw VerificationException(id, "Credential '$id' is expired")

        if (vc.validFrom != null && vc.validFrom!! > now)
            throw VerificationException(id, "Credential '$id' is not yet valid")

        if (vcp?.sub != null) {
            val vcJson = vc.toJson()
            // [TODO #302] Keycloak issues oid4vc_identity_credential with no id value
            // https://github.com/tdiesler/nessus-identity/issues/302
            val subId = CredentialMatcher.pathValues("$vcJson", "$.credentialSubject.id").firstOrNull()
            if (subId != null && subId != vcp.sub)
                error("Unexpected subject id: $subId")
        }

        if (vcp?.types?.isNotEmpty() ?: false) {
            val vcJson = vc.toJson()
            val vcTypes = CredentialMatcher.pathValues("$vcJson", "$.type")
            if (!vcTypes.containsAll(vcp.types))
                error("Unexpected credential types: $vcTypes")
        }
    }
}