package io.nessus.identity.minisrv

import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.service.CredentialOfferRegistry.hasCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialRequestDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.UserRole
import io.nessus.identity.utils.urlQueryToMap
import kotlinx.serialization.json.*

class IssuerApiHandler(val issuerSvc: NativeIssuerService):
    AuthorizationApiHandler(UserRole.Issuer, issuerSvc.authorizationSvc) {

    val adminContext = issuerSvc.adminContext

    companion object {
        suspend fun handleIssuerMetadataRequest(call: RoutingCall, issuerSvc: IssuerService) {
            val issuerMetadata = issuerSvc.getIssuerMetadata()
            val payload = Json.encodeToString(issuerMetadata)
            call.respondText(
                status = HttpStatusCode.OK,
                contentType = ContentType.Application.Json,
                text = payload
            )
        }
    }

    suspend fun handleAuthorizationMetadataRequest(call: RoutingCall) {
        handleAuthorizationMetadataRequest(call, adminContext)
    }

    suspend fun handleAuthorize(call: RoutingCall) {

        val ctx = adminContext
        val authContext = ctx.getAuthContext()
        val issuerMetadata = issuerSvc.getIssuerMetadata() as IssuerMetadataDraft11
        authContext.putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

        val queryParams = urlQueryToMap(call.request.uri)
        val authRequest = AuthorizationRequestDraft11.fromHttpParameters(queryParams)

        val responseType = authRequest.responseType
        when (responseType) {
            "code" -> {
                val redirectUri = requireNotNull(authRequest.redirectUri) { "No redirect_uri" }
                val authRequestOut = authorizationSvc.createIDTokenRequest(ctx, authRequest)
                return call.respondRedirect(authRequestOut.toRequestUrl(redirectUri))
            }
            else -> {
                call.respondText(
                    status = HttpStatusCode.InternalServerError,
                    contentType = ContentType.Text.Plain,
                    text = "Unknown AuthorizationRequest"
                )
            }
        }
    }

    suspend fun handleCredentialRequest(call: RoutingCall) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequestDraft11>()
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = issuerSvc.getCredentialFromRequest(credReq, accessTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleCredentialRequestDeferred(call: RoutingCall) {

        val acceptanceToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val acceptanceTokenJwt = SignedJWT.parse(acceptanceToken)
        val credentialResponse = issuerSvc.getCredentialFromAcceptanceToken(acceptanceTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleDirectPost(call: RoutingCall) {
        handleDirectPost(call, adminContext)
    }

    suspend fun handleJwksRequest(call: RoutingCall) {
        handleJwksRequest(call, adminContext)
    }

    suspend fun handleTokenRequest(call: RoutingCall) {

        val ctx = adminContext
        val authContext = ctx.getAuthContext()
        val issuerMetadata = issuerSvc.getIssuerMetadata() as IssuerMetadataDraft11
        authContext.putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)

        val postParams = call.receiveParameters().toMap().toMutableMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val preAuthCode = postParams["pre-authorized_code"]?.firstOrNull()
        if (preAuthCode != null && isEBSIPreAuthorizedType(preAuthCode)) {

            // [TODO] remove on-demand CredentialOffer creation
            // In the EBSI Issuer Conformance Test, the preAuthCode is a known Credential type
            // and the clientId associated with the TokenRequest is undefined

            val ebsiConfig = requireEbsiConfig()
            val clientId = ebsiConfig.requesterDid as String
            postParams["client_id"] = listOf(clientId)

            // Issuing CredentialOffers (on-demand) for EBSI Conformance
            if (!hasCredentialOfferRecord(preAuthCode)) {
                val userPin = postParams["user_pin"]?.firstOrNull()
                log.info { "Issuing CredentialOffer $preAuthCode (on-demand) for EBSI Conformance" }
                val credOffer = issuerSvc.createCredentialOffer(preAuthCode, clientId, preAuthorized = true, userPin = userPin)
                putCredentialOfferRecord(preAuthCode, credOffer, userPin)
            }
        }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = authorizationSvc.getTokenResponse(ctx, tokenRequest)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokenResponse)
        )
    }
}