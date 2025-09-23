package io.nessus.identity.openapi

import io.nessus.identity.types.CredentialOffer

// IssuerApi ==========================================================================================================

interface IssuerApi {

    /**
     * Create a CredentialOffer for the given parameters.
     */
    suspend fun createCredentialOffer(
        subjectId: String,
        credentialConfigurationIds: List<String>,
    ): CredentialOffer
}
