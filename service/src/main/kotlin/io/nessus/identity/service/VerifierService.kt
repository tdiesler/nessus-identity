package io.nessus.identity.service

import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.W3CCredentialV11Jwt

// VerifierService =====================================================================================================

interface VerifierService {

    val verifierEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/verifier"
            else -> requireVerifierConfig().baseUrl
        }

    fun validateVerifiableCredential(vpcJwt: W3CCredentialV11Jwt, vcp: CredentialParameters? = null)

    companion object {
        fun create(): DefaultVerifierService {
            return DefaultVerifierService()
        }
    }
}
