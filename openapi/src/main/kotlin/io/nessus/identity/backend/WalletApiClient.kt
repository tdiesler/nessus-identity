package io.nessus.identity.backend

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.ContentType.*
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.handleResponse
import io.nessus.identity.waltid.http
import kotlinx.serialization.json.JsonObject

// WalletApiClient ====================================================================================================

class WalletApiClient(val ctx: LoginContext) : WalletApi {

    val baseUrl = "http://localhost:7000"

    override suspend fun listCredentialOffers(): List<CredentialOfferDraft17> {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credential-offers") {
            contentType(Application.Json)
        }
        return handleResponse<List<CredentialOfferDraft17>>(res)
    }

    override suspend fun addCredentialOffer(offer: CredentialOffer): String {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credential-offers/receive") {
            parameter("credential_offer", offer.toJson())
        }
        return handleResponse<String>(res)
    }

    override suspend fun fetchCredentialFromOffer(offerId: String): JsonObject {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credentials/fetch") {
            contentType(Application.Json)
            parameter("credential_offer_id", offerId)
        }
        return handleResponse<JsonObject>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
