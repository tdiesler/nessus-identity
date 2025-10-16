package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.VCDataV11Jwt

// VerifierService =====================================================================================================

interface VerifierService {

    fun validateVerifiableCredential(vpcJwt: VCDataV11Jwt, vcp: CredentialParameters? = null)

    companion object {
        fun createEbsi(): VerifierServiceEbsi32 {
            return VerifierServiceEbsi32()
        }
        fun createKeycloak(): VerifierServiceKeycloak {
            return VerifierServiceKeycloak()
        }
    }
}
