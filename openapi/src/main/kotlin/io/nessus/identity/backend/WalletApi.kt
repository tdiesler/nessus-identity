package io.nessus.identity.backend

import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft17
import kotlinx.serialization.json.JsonObject

// WalletApi ==========================================================================================================

interface WalletApi {

    /**
     * Get available CredentialOffers for the given walletId.
     */
    suspend fun listCredentialOffers(): List<CredentialOfferDraft17>

    /**
     * Receives a CredentialOffer for the given walletId.
     *
     * The Wallet can publish a credential_offer_endpoint
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata
     *
     * The Issuer can then send the CredentialOffer as a single URI query parameter, either credential_offer or credential_offer_uri
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer
     */
    suspend fun addCredentialOffer(
        offer: CredentialOffer
    ): String

    /**
     * Fetches the Credential from the Issuer for the given CredentialOffer id.
     * Uses the in-time authorization flow.
     */
    suspend fun fetchCredentialFromOffer(
        offerId: String
    ): JsonObject
}
