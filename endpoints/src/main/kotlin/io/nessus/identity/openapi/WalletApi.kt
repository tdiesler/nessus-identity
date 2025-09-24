package io.nessus.identity.openapi

import io.nessus.identity.types.CredentialOffer
import kotlinx.serialization.json.JsonObject

// WalletApi ==========================================================================================================

interface WalletApi {

    /**
     * Receives a CredentialOffer for the given walletId.
     *
     * The Wallet can publish a credential_offer_endpoint
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata
     *
     * The Issuer can then send the CredentialOffer as a single URI query parameter, either credential_offer or credential_offer_uri
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer
     */
    suspend fun receiveCredentialOffer(
        walletId: String,
        offer: CredentialOffer
    ): String

    /**
     * Fetches the Credential from the Issuer for the given CredentialOffer id.
     * Uses the in-time authorization flow.
     */
    suspend fun fetchCredentialFromOffer(
        walletId: String,
        offerId: String
    ): JsonObject
}
