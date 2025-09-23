package io.nessus.identity.openapi

import io.nessus.identity.types.CredentialOffer

// WalletApi ==========================================================================================================

interface WalletApi {

    /**
     * Receives a CredentialOffer for the given walletId.
     */
    suspend fun receiveCredentialOffer(
        walletId: String,
        offer: CredentialOffer
    ): String
}
