package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.ebsi.SessionsStore.requireLoginContext
import io.nessus.identity.extend.getPreAuthorizedGrantDetails
import io.nessus.identity.extend.toSignedJWT
import io.nessus.identity.service.CredentialOfferRegistry.getCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.urlQueryToMap

object WalletHandler {

    val log = KotlinLogging.logger {}

    val walletSrv = WalletService.create()

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
            val ctx = OIDContext(requireLoginContext(dstId))
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
    private suspend fun handleCredentialOffer(call: RoutingCall, ctx: OIDContext) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        val credOffer = walletSrv.getCredentialOfferFromUri(ctx, oid4vcOfferUri)
        val offeredCred = walletSrv.resolveOfferedCredential(ctx, credOffer)

        // Init with the default UserPin for EBSI Credential types
        if (credOffer.getPreAuthorizedCodeGrant() != null) {
            val authCode = credOffer.getPreAuthorizedCodeGrant()?.preAuthorizedCode as String
            val ebsiType = offeredCred.types?.firstOrNull { isEBSIPreAuthorizedType(it) }
            if (ebsiType != null) {
                val cor = getCredentialOfferRecord(ebsiType)
                var userPin = cor?.userPin
                if (userPin == null) {
                    userPin = System.getenv("EBSI__PREAUTHORIZED_PIN")
                        ?: throw IllegalStateException("No EBSI__PREAUTHORIZED_PIN")
                }
                putCredentialOfferRecord(authCode, credOffer, userPin)
            }
        }

        var credRes = walletSrv.getCredentialFromOffer(ctx, credOffer)

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
            credRes = walletSrv.getDeferredCredential(ctx, acceptanceToken)
            credJwt = credRes.toSignedJWT()
        }

        if (credJwt == null)
            throw IllegalStateException("No Credential JWT")

        walletSrv.addCredential(ctx, credRes)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }
}