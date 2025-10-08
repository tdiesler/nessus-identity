package io.nessus.identity.openapi.wallet

import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft17
import kotlinx.serialization.json.JsonObject

// WalletApi ==========================================================================================================

interface WalletApi {

    /**
     * Accept a CredentialOffer and fetch the associated Credential from the Issuer.
     * Uses the in-time authorization flow.
     */
    suspend fun acceptCredentialOffer(
        ctx: LoginContext,
        offerId: String
    ): JsonObject

    /**
     * Add a CredentialOffer to the Wallet.
     *
     * The Wallet can publish a credential_offer_endpoint
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-client-metadata
     *
     * The Issuer can then send the CredentialOffer as a single URI query parameter, either credential_offer or credential_offer_uri
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer
     */
    suspend fun addCredentialOffer(
        ctx: LoginContext,
        offer: CredentialOffer
    ): String

    /**
     * Get available CredentialOffers
     */
    suspend fun getCredentialOffers(
        ctx: LoginContext
    ): Map<String, CredentialOfferDraft17>

    /**
     * Delete a CredentialOffer from the Wallet.
     */
    suspend fun deleteCredentialOffer(
        ctx: LoginContext,
        offerId: String
    ): JsonObject?

    /**
     * Get available Credentials
     */
    suspend fun getCredentials(
        ctx: LoginContext
    ): Map<String, JsonObject>

    /**
     * Get a Credential by id
     */
    suspend fun getCredential(
        ctx: LoginContext,
        vcId: String
    ): JsonObject?
}
