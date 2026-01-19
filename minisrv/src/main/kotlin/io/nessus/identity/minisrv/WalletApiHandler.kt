package io.nessus.identity.minisrv

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.Features
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_AUTO_FETCH
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_STORE
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.UserRole
import io.nessus.identity.utils.http

class WalletApiHandler(val walletSvc: WalletService):
    AuthorizationApiHandler(UserRole.Holder, walletSvc.authorizationSvc) {

    suspend fun handleCredentialOfferReceive(call: RoutingCall, ctx: LoginContext) {

        var credOfferJson = call.request.queryParameters["credential_offer"]
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]

        if (credOfferUri != null) {

            log.info { "Received CredentialOfferUri: $credOfferUri" }
            val credOfferUriRes = http.get(credOfferUri)

            credOfferJson = credOfferUriRes.bodyAsText()
            if (credOfferUriRes.status.value !in 200..202) {
                error("Error sending credential Offer: ${credOfferUriRes.status.value} - $credOfferJson")
            }
        }

        requireNotNull(credOfferJson) { "No credential_offer" }

        log.info { "Received CredentialOffer: $credOfferJson" }
        val credOffer = CredentialOffer.fromJson(credOfferJson)

        if (Features.isEnabled(CREDENTIAL_OFFER_STORE)) {
            walletSvc.addCredentialOffer(ctx, credOffer)
        }
        if (Features.isEnabled(CREDENTIAL_OFFER_AUTO_FETCH)) {
            val credJwt = walletSvc.getCredentialFromOffer(ctx, credOffer)
            call.respondText(
                status = HttpStatusCode.Accepted,
                contentType = ContentType.Application.Json,
                text = "${credJwt.toJson()}"
            )
        } else {
            call.respondRedirect("${walletSvc.endpointUri}/credential-offers")
        }
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}