package io.nessus.identity.openapi.wallet

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.ContentType.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.http
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.handleResponse
import kotlinx.serialization.json.JsonObject

// WalletApiClient ====================================================================================================

class WalletApiClient() : WalletApi {

    val baseUrl: String

    init {
        val walletApi = ConfigProvider.requireWalletApiConfig()
        baseUrl = walletApi.baseUrl
    }

    override suspend fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOfferDraft17> {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credential-offers") {
            contentType(Application.Json)
        }
        return handleResponse<Map<String, CredentialOfferDraft17>>(res)
    }

    override suspend fun addCredentialOffer(ctx: LoginContext, offer: CredentialOffer): String {
        val res = http.put("$baseUrl/wallets/${ctx.walletId}/credential-offer") {
            parameter("credential_offer", offer.toJson())
        }
        return handleResponse<String>(res)
    }

    override suspend fun acceptCredentialOffer(ctx: LoginContext, offerId: String): JsonObject {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credential-offer/${offerId}/accept") {
            contentType(Application.Json)
        }
        return handleResponse<JsonObject>(res)
    }

    override suspend fun deleteCredentialOffer(ctx: LoginContext, offerId: String): JsonObject {
        val res = http.delete("$baseUrl/wallets/${ctx.walletId}/credential-offer/${offerId}") {
            contentType(Application.Json)
        }
        return handleResponse<JsonObject>(res)
    }

    override suspend fun getCredentials(ctx: LoginContext): Map<String, JsonObject> {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credentials") {
            contentType(Application.Json)
        }
        return handleResponse<Map<String, JsonObject>>(res)
    }

    override suspend fun getCredential(ctx: LoginContext, credId: String): JsonObject? {
        val res = http.get("$baseUrl/wallets/${ctx.walletId}/credential/$credId") {
            contentType(Application.Json)
        }
        return handleResponse<JsonObject>(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------
}
