package io.nessus.identity.service

import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.W3CCredentialV11Jwt

// VerifierService =====================================================================================================

interface VerifierService {

    fun validateVerifiableCredential(vpcJwt: W3CCredentialV11Jwt, vcp: CredentialParameters? = null)

    companion object {
        fun createEbsi(): VerifierServiceEbsi32 {
            return VerifierServiceEbsi32()
        }
        fun createKeycloak(): VerifierServiceKeycloak {
            return VerifierServiceKeycloak()
        }
    }
}
