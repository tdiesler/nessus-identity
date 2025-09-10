package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.W3CCredential

// VerifierService =====================================================================================================

interface VerifierService {

    fun validateVerifiableCredential(vc: W3CCredential, vcp: CredentialParameters? = null)

    companion object {
        fun create(): VerifierService {
            return DefaultVerifierService()
        }
    }
}
