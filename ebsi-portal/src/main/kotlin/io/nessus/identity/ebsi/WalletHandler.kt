package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.path
import io.ktor.server.request.uri
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.ebsi.SessionsStore.requireLoginContext
import io.nessus.identity.extend.getPreAuthorizedGrantDetails
import io.nessus.identity.extend.toSignedJWT
import io.nessus.identity.service.CredentialOfferRegistry.getCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.IssuerService.defaultUserPin
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.urlQueryToMap

object WalletHandler {

    val log = KotlinLogging.logger {}

    // Handle Wallet requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleWalletRequests(call: RoutingCall, dstId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Wallet $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        // Handle CredentialOffer by Uri
        //
        if (path == "/wallet/$dstId" && queryParams["credential_offer_uri"] != null) {
            val ctx = OIDCContext(requireLoginContext(dstId))
            return handleCredentialOffer(call, ctx)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Private ---------------------------------------------------------------------------------------------------------

    // Request and present Verifiable Credentials
    // https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows
    //
    // Issuer initiated flows start with the Credential Offering proposed by Issuer.
    // The Credential Offering is in redirect for same-device tests and in QR Code for cross-device tests.
    //
    private suspend fun handleCredentialOffer(call: RoutingCall, ctx: OIDCContext) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        val credOffer = WalletService.getCredentialOfferFromUri(ctx, oid4vcOfferUri)
        val offeredCred = WalletService.resolveOfferedCredential(ctx, credOffer)

        // Init with the default UserPin for EBSI Credential types
        if (credOffer.getPreAuthorizedGrantDetails() != null) {
            val authCode = credOffer.getPreAuthorizedGrantDetails()?.preAuthorizedCode as String
            val ebsiType = offeredCred.types?.firstOrNull { isEBSIPreAuthorizedType(it) }
            if (ebsiType != null) {
                val userPin = getCredentialOfferRecord(ebsiType)?.userPin ?: defaultUserPin
                putCredentialOfferRecord(authCode, credOffer, userPin)
            }
        }

        var credRes = WalletService.getCredentialFromOffer(ctx, credOffer)

        // In-Time CredentialResponses MUST have a 'format'
        var credJwt: SignedJWT? = null
        if (credRes.format != null) {
            credJwt = credRes.toSignedJWT()
        }

        // Deferred CredentialResponses have an 'acceptance_token'
        else if (credRes.acceptanceToken != null) {
            // The credential will be available with a delay of 5 seconds from the first Credential Request.
            Thread.sleep(5500)
            val acceptanceToken = credRes.acceptanceToken as String
            credRes = WalletService.getDeferredCredential(ctx, acceptanceToken)
            credJwt = credRes.toSignedJWT()
        }

        if (credJwt == null)
            throw IllegalStateException("No Credential JWT")

        WalletService.addCredential(ctx, credRes)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }
}