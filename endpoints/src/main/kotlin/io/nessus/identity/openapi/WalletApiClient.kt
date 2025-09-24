package io.nessus.identity.openapi

import io.ktor.client.request.*
import io.ktor.http.*
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.waltid.handleResponse
import io.nessus.identity.waltid.http

// WalletApiClient ====================================================================================================

class WalletApiClient: WalletApi {

    val baseUrl = "http://localhost:8080"

    /**
     * Receives a CredentialOffer for the given walletId.
     */
    override suspend fun receiveCredentialOffer(walletId: String, offer: CredentialOffer): String {
        val res = http.get("$baseUrl/wallets/${walletId}/receive") {
            parameter("credential_offer", offer.toJson())
        }
        return handleResponse<String>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
