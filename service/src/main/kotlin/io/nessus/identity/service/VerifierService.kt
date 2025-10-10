package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.VCDataV11

// VerifierService =====================================================================================================

interface VerifierService {

    fun validateVerifiableCredential(vc: VCDataV11, vcp: CredentialParameters? = null)

    companion object {
        fun createEbsi(): VerifierServiceEbsi32 {
            return VerifierServiceEbsi32()
        }
    }
}
