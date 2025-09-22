package io.nessus.identity.api

import io.nessus.identity.types.CredentialOffer

// WalletAPI ==========================================================================================================

interface WalletAPI {

    /**
     * Receives a CredentialOffer for the given walletId.
     */
    suspend fun receiveCredentialOffer(
        walletId: String,
        offer: CredentialOffer
    ): String

    /**
     * Receives a CredentialOffer for the given walletId.
     */
//    suspend fun requestCredentialOffer(
//        walletId: String,
//        issuerUrl: String,
//        subjectId: String,
//        credentialConfigurationIds: List<String>,
//    ): String
}
