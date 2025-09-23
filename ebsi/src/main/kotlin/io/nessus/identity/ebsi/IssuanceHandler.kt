package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.CredentialRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.ebsi.SessionsStore.requireLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.OIDCContextRegistry
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.waltid.User
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

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            val ctx = OIDContext(requireLoginContext(dstId))
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
            return handleCredentialRequestDeferred(call, ctx)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun handleCredentialRequest(call: RoutingCall, ctx: OIDContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val issuerSvc = IssuerService.create(ctx)
        val credReq = call.receive<CredentialRequest>()
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = issuerSvc.getCredentialFromRequest(credReq, accessTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    private suspend fun handleCredentialRequestDeferred(call: RoutingCall, ctx: OIDContext) {

        val acceptanceToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val issuerSvc = IssuerService.create(ctx)
        val acceptanceTokenJwt = SignedJWT.parse(acceptanceToken)
        val credentialResponse = issuerSvc.getDeferredCredentialFromAcceptanceToken(acceptanceTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    private suspend fun handleIssuerMetadataRequest(call: RoutingCall, ctx: OIDContext) {

        val issuerSvc = IssuerService.create(ctx)
        val metadata = issuerSvc.getIssuerMetadata()
        val payload = Json.encodeToString(metadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }
}