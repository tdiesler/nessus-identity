package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.VerifiableCredentialV10

// VerifierService =====================================================================================================

interface VerifierService {

    fun validateVerifiableCredential(vc: VerifiableCredentialV10, vcp: CredentialParameters? = null)

    companion object {
        fun createEbsi(): VerifierServiceEbsi32 {
            return VerifierServiceEbsi32()
        }
    }
}
