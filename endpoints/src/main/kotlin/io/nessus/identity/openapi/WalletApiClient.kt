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
        val res = http.post("$baseUrl/wallets/${walletId}/credential-offer") {
            contentType(ContentType.Application.Json)
            setBody(offer)
        }
        return handleResponse<String>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
