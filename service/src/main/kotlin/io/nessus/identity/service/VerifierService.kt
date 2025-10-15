package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.VCDataV11

// VerifierService =====================================================================================================

interface VerifierService {

    companion object {
        fun createEbsi(): VerifierServiceEbsi32 {
            return VerifierServiceEbsi32()
        }
        fun createKeycloak(): VerifierServiceKeycloak {
            return VerifierServiceKeycloak()
        }
    }
}
