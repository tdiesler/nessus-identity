package io.nessus.identity.openapi

import io.ktor.client.request.*
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.waltid.handleResponse
import io.nessus.identity.waltid.http
import kotlinx.serialization.json.JsonObject

// WalletApiClient ====================================================================================================

class WalletApiClient: WalletApi {

    val baseUrl = "http://localhost:8080"

    /**
     * Receives a CredentialOffer for the given walletId.
     */
    override suspend fun receiveCredentialOffer(walletId: String, offer: CredentialOffer): String {
        val res = http.get("$baseUrl/wallets/${walletId}/credential-offer/receive") {
            parameter("credential_offer", offer.toJson())
        }
        return handleResponse<String>(res)
    }

    /**
     * Fetch a Credential for the given CredentialOffer id.
     */
    override suspend fun fetchCredentialFromOffer(walletId: String, offerId: String): JsonObject {
        val res = http.get("$baseUrl/wallets/${walletId}/credential/fetch") {
            parameter("credential_offer_id", offerId)
        }
        return handleResponse<JsonObject>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
