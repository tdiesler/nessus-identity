package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.ebsi.SessionsStore.requireLoginContext
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.AuthServiceEbsi32
import io.nessus.identity.service.AuthServiceEbsi32.Companion.authEndpointUri
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDCContextRegistry
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.Json

// Handle OIDC for VC/VP Requests ======================================================================================
//
object OAuthHandler {

    val log = KotlinLogging.logger {}

    suspend fun handleAuthRequests(call: RoutingCall, dstId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Auth $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        if (path.endsWith(".well-known/openid-configuration")) {
            val ctx = OIDContext(requireLoginContext(dstId))
            return handleAuthorizationMetadataRequest(call, ctx)
        }

        // AuthorizationRequest endpoint
        //
        if (path == "/auth/$dstId/authorize") {
            val ctx = OIDContext(requireLoginContext(dstId))
            return handleAuthorizationRequest(call, ctx)
        }

        // direct_post
        //
        if (path == "/auth/$dstId/direct_post") {
            val ctx = OIDCContextRegistry.assert(dstId)
            return handleAuthDirectPost(call, ctx)
        }

        // JWKS endpoint
        //
        if (path == "/auth/$dstId/jwks") {
            val ctx = requireLoginContext(dstId)
            return handleAuthJwksRequest(call, ctx)
        }

        // Token endpoint
        //
        if (path == "/auth/$dstId/token") {
            return handleAuthTokenRequest(call, dstId)
        }

        // Callback as part of the AuthorizationRequest
        //
        if (path == "/auth/$dstId") {
            val ctx = OIDCContextRegistry.assert(dstId)
            val responseType = queryParams["response_type"]
            return when (responseType) {
                "id_token" -> handleIDTokenRequest(call, ctx)
                "vp_token" -> handleVPTokenRequest(call, ctx)
                else -> throw IllegalArgumentException("Unknown response type: $responseType")
            }
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: OIDContext) {

        val authSvc = AuthServiceEbsi32.create(ctx)
        val payload = Json.encodeToString(authSvc.getAuthMetadata())
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    /**
     * The Holder requests access for the required credentials from the Issuer's Authorisation Server
     */
    private suspend fun handleAuthorizationRequest(call: RoutingCall, ctx: OIDContext) {

        val queryParams = call.parameters.toMap()
        val authReq = AuthorizationRequest.fromHttpParameters(queryParams)
        log.info { "Authorization Request: ${Json.encodeToString(authReq)}" }
        queryParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val authSvc = AuthServiceEbsi32.create(ctx)
        authSvc.validateAuthorizationRequest(authReq)
        val isVPTokenRequest = authReq.scope.any { it.contains("vp_token") }
        val redirectUrl = if (isVPTokenRequest) {
            val vpTokenReqJwt = authSvc.buildVPTokenRequest(authReq)
            authSvc.buildVPTokenRedirectUrl(vpTokenReqJwt)
        } else {
            val idTokenReqJwt = authSvc.buildIDTokenRequest(authReq)
            authSvc.buildIDTokenRedirectUrl(idTokenReqJwt)
        }
        call.respondRedirect(redirectUrl)
    }

    private suspend fun handleIDTokenRequest(call: RoutingCall, ctx: OIDContext) {

        val reqParams = urlQueryToMap(call.request.uri).toMutableMap()
        val redirectUri = reqParams["redirect_uri"] as String

        // Replace IDToken request params with the response from request_uri
        reqParams["request_uri"]?.also { requestUri ->
            log.info { "IDToken params from: $requestUri" }
            val res = http.get(requestUri)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val uriRes = res.bodyAsText()
            log.info { "UriResponse: $uriRes" }
            val resJwt = SignedJWT.parse(uriRes)
            log.info { "UriResponse Header: ${resJwt.header}" }
            log.info { "UriResponse Claims: ${resJwt.jwtClaimsSet}" }
            for ((k, v) in resJwt.jwtClaimsSet.claims) {
                reqParams[k] = "$v"
            }
        }

        val walletSvc = WalletService.createEbsi()
        val idTokenJwt = walletSvc.createIDToken(ctx, reqParams)
        walletSvc.sendIDToken(ctx, redirectUri, idTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleVPTokenRequest(call: RoutingCall, ctx: OIDContext) {

        val reqParams = urlQueryToMap(call.request.uri)

        // Final Qualification Credential use case ...
        //
        //  - EBSI offers the CTWalletQualificationCredential
        //  - Holder sends an AuthorizationRequest, EBSI responds with an 302 Redirect (WalletService.sendAuthorizationRequest)
        //  - Cloudflare may deny that redirect URL because of a very large 'request' query parameter
        //  - The content of that request parameter is a serialized AuthorizationRequest object
        //  - We rewrite the redirect URL using a request_uri parameter, which resolves to that AuthorizationRequest
        //  - Here, we restore that AuthorizationRequest and use it's PresentationDefinition to build the VPToken

        // [TODO #229] Access to request_uri object not thread safe
        // https://github.com/tdiesler/nessus-identity/issues/229

        var authReq = ctx.assertAttachment(AUTH_REQUEST_ATTACHMENT_KEY)

        val requestUri = reqParams["request_uri"]
        if (requestUri != null) {

            if (!requestUri.startsWith(authEndpointUri))
                throw IllegalStateException("Unexpected request_uri: $requestUri")

            urlQueryToMap(requestUri)["request_object"]
                ?: throw IllegalStateException("No request_object in: $requestUri")

            authReq = ctx.assertAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY) as AuthorizationRequest
        }

        val walletSvc = WalletService.createEbsi()
        val vpTokenJwt = walletSvc.createVPToken(ctx, authReq)
        walletSvc.sendVPToken(ctx, vpTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleAuthDirectPost(call: RoutingCall, ctx: OIDContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Auth DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val authSvc = AuthServiceEbsi32.create(ctx)
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val authCode = authSvc.validateIDToken(idTokenJwt)
            val redirectUrl = authSvc.buildAuthCodeRedirectUri(authCode)
            return call.respondRedirect(redirectUrl)
        }

        if (postParams["vp_token"] != null) {
            val redirectUrl = VerificationHandler.handleVPTokenResponse(ctx, postParams)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    private suspend fun handleAuthJwksRequest(call: RoutingCall, ctx: LoginContext) {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val keys = mapOf("keys" to listOf(keyJwk))
        val payload = Json.encodeToString(keys)

        log.info { "Jwks $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    private suspend fun handleAuthTokenRequest(call: RoutingCall, dstId: String) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenReq = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = when (tokenReq) {
            is TokenRequest.AuthorizationCode -> {
                val ctx = OIDCContextRegistry.assert(dstId)
                val authSvc = AuthServiceEbsi32.create(ctx)
                authSvc.handleTokenRequestAuthCode(tokenReq)
            }

            is TokenRequest.PreAuthorizedCode -> {
                val ctx = OIDContext(requireLoginContext(dstId))
                val authSvc = AuthServiceEbsi32.create(ctx)
                authSvc.handleTokenRequestPreAuthorized(tokenReq)
            }
        }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokenResponse)
        )
    }
}