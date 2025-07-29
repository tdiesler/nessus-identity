package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.CredentialRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.path
import io.ktor.server.request.receive
import io.ktor.server.request.uri
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.ebsi.SessionsStore.requireLoginContext
import io.nessus.identity.service.CredentialOfferRegistry.hasCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.IssuerService.ebsiDefaultHolderId
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.OIDCContextRegistry
import io.nessus.identity.service.urlQueryToMap
import kotlinx.serialization.json.Json

object IssuanceHandler {

    val log = KotlinLogging.logger {}

    // Handle Issuer Requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleIssuerRequests(call: RoutingCall, dstId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Issuer $reqUri" }
        urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val ctx = requireLoginContext(dstId)

        // Issuing CredentialOffers for EBSI Conformance
        //
        listOf("CTWalletSamePreAuthorisedInTime", "CTWalletSamePreAuthorisedDeferred").forEach { ct ->
            if (!hasCredentialOfferRecord(ct)) {
                log.info { "Issuing CredentialOffer $ct for EBSI Conformance" }
                val userPin = "7760"
                val subId = ebsiDefaultHolderId
                val types = listOf("VerifiableCredential", "VerifiableAttestation", ct)
                val credOffer = IssuerService.createCredentialOffer(ctx, subId, types, userPin)
                putCredentialOfferRecord(ct, credOffer, userPin)
            }
        }

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            return handleIssuerMetadataRequest(call, ctx)
        }

        // Handle Credential Request
        //
        if (path == "/issuer/$dstId/credential") {
            val ctx = OIDCContextRegistry.assert(dstId)
            return handleCredentialRequest(call, ctx)
        }

        // Handle Deferred Credential Request
        //
        if (path == "/issuer/$dstId/credential_deferred") {
            val ctx = OIDCContextRegistry.assert(dstId)
            return handleDeferredCredentialRequest(call, ctx)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun handleCredentialRequest(call: RoutingCall, ctx: OIDCContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequest>()
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = IssuerService.credentialFromRequest(ctx, credReq, accessTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    private suspend fun handleDeferredCredentialRequest(call: RoutingCall, ctx: OIDCContext) {

        val acceptanceToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val acceptanceTokenJwt = SignedJWT.parse(acceptanceToken)
        val credentialResponse = IssuerService.deferredCredentialFromAcceptanceToken(ctx, acceptanceTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    private suspend fun handleIssuerMetadataRequest(call: RoutingCall, ctx: LoginContext) {

        val issuerMetadata = IssuerService.getIssuerMetadata(ctx)
        val payload = Json.encodeToString(issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }
}