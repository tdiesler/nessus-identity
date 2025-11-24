package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.Features
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_AUTO_FETCH
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_STORE
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.KNOWN_ISSUER_EBSI_V3
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext.Companion.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlDecode
import io.nessus.identity.service.urlEncode
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import kotlinx.serialization.json.*

class WalletHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc: WalletService = WalletService.createKeycloak()

    fun walletModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val model = ctx?.let { BaseModel().withLoginContext(ctx) }
            ?: BaseModel().withLoginContext(call, UserRole.Holder)
        val modelLogin = model.loginContext
        model.also {
            it["holderName"] = modelLogin.walletInfo.name
            it["holderDid"] = modelLogin.didInfo.did
            it["targetId"] = modelLogin.targetId
        }
        return model
    }

    suspend fun showHome(call: RoutingCall) {
        val model = walletModel(call)
        call.respond(
            FreeMarkerContent("wallet_home.ftl", model)
        )
    }

    suspend fun showLoginPage(call: RoutingCall) {
        val model = walletModel(call)
        call.respond(
            FreeMarkerContent("wallet_login.ftl", model)
        )
    }

    suspend fun handleLogin(call: RoutingCall) {
        val params = call.receiveParameters()
        val email = params["email"] ?: error("No email")
        val password = params["password"] ?: error("No password")
        val loginParams = LoginParams(LoginType.EMAIL, email, password)
        SessionsStore.createLoginContext(call, UserRole.Holder, loginParams)
        call.respondRedirect("/wallet")
    }

    suspend fun handleLogout(call: RoutingCall) {
        SessionsStore.logout(call, UserRole.Holder)
        call.respondRedirect("/wallet")
    }

    /**
     * /wallet/auth/callback
     * /wallet/auth/callback/{targetId}
     */
    suspend fun handleAuthCallback(call: RoutingCall, ctx: LoginContext) {

        log.info { "Auth Callback: ${call.request.uri}" }
        val authContext = ctx.getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) as AuthorizationContext

        val authCode = call.parameters["code"]
        if (authCode != null) {
            val authCode = call.parameters["code"] ?: error("No code")
            // [TODO] Do we really always want to fetch the credential in the auth callback
            val accessToken = walletSvc.getAccessTokenFromAuthorizationCode(authContext, authCode)
            val credJwt = walletSvc.getCredential(authContext, accessToken)
            return call.respondRedirect("/wallet/${ctx.targetId}/credential/${credJwt.vcId}")
        }

        val error = call.parameters["error"]
        if (error != null) {
            val errorMessage = call.parameters["error_description"]
                ?.let { urlDecode(it) } ?: error
            error("Authentication Error: $errorMessage")
        }

        val responseType = call.parameters["response_type"]
        return when (responseType) {
            "id_token" -> handleIDTokenRequest(call, ctx)
            //"vp_token" -> handleVPTokenRequest(call, ctx)
            else -> error("Unknown response type: $responseType")
        }
    }

    suspend fun handleAuthDirectPost(call: RoutingCall, ctx: LoginContext) {
        val authSvc = walletSvc.authorizationSvc

        val postParams = call.receiveParameters().toMap()
        log.info { "Auth DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val authCode = authSvc.validateIDToken(ctx, idTokenJwt)
            val redirectUrl = authSvc.buildAuthCodeRedirectUri(ctx, authCode)
            return call.respondRedirect(redirectUrl)
        }

//        if (postParams["vp_token"] != null) {
//            val redirectUrl = VerificationHandler.handleVPTokenResponse(ctx, postParams)
//            return call.respondRedirect(redirectUrl)
//        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    suspend fun handleIDTokenRequest(call: RoutingCall, ctx: LoginContext) {

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

        val authSvc = walletSvc.authorizationSvc
        val idTokenJwt = authSvc.createIDToken(ctx, reqParams)
        authSvc.sendIDToken(ctx, redirectUri, idTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    suspend fun handleAuthorization(call: RoutingCall, ctx: LoginContext) {
        when (val responseType = call.parameters["response_type"]) {
            "vp_token" -> handleAuthVPTokenRequest(call, ctx)
            else -> error("Unexpected response_type: $responseType")
        }
    }

    suspend fun handleAuthFlow(call: RoutingCall, ctx: LoginContext, flowStep: String) {
        when (flowStep) {
            "vp-token-consent" -> handleAuthVPTokenConsent(call, ctx)
            else -> error("Unknown flow step: $flowStep")
        }
    }

    suspend fun handleCredentialOfferReceive(call: RoutingCall, targetId: String) {

        // An unsolicited call by the Issuer would likely not have a session cookie from which we can derive the target Holder wallet.
        // Instead, we expect to find a Holder LoginContext for the given targetId.
        val ctx = requireLoginContext(call, UserRole.Holder, targetId)

        val credOfferJson = call.request.queryParameters["credential_offer"]
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]

        val credOffer = if (credOfferJson != null) {

            CredentialOffer.fromJson(credOfferJson)

        } else if (credOfferUri != null) {

            val credOfferUriRes = http.get(credOfferUri)
            val bodyAsText = credOfferUriRes.bodyAsText()
            if (credOfferUriRes.status.value !in 200..201) {
                error("Error sending credential Offer: ${credOfferUriRes.status.value} - $bodyAsText")
            }
            CredentialOffer.fromJson(bodyAsText)

        } else {
            error("No credential_offer")
        }
        log.info { "Received CredentialOffer: ${credOffer.toJson()}" }

        if (Features.isEnabled(CREDENTIAL_OFFER_STORE)) {
            walletSvc.addCredentialOffer(ctx, credOffer)
        }
        if (Features.isEnabled(CREDENTIAL_OFFER_AUTO_FETCH)) {
            val authContext = walletSvc.createAuthorizationContext(ctx).withCredentialOffer(credOffer)
            val accessToken = walletSvc.getAccessTokenFromCredentialOffer(authContext, credOffer)
            val credJwt = walletSvc.getCredential(authContext, accessToken)
            call.respondText(
                status = HttpStatusCode.Accepted,
                contentType = ContentType.Application.Json,
                text = "${credJwt.toJson()}"
            )
        } else {
            call.respondRedirect("/wallet/$targetId/credential-offers")
        }
    }

    suspend fun handleCredentialOfferAccept(call: RoutingCall, ctx: LoginContext, offerId: String) {

        // Load the Credential Offer from storage
        //
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId)
            ?: error("No credential_offer for: $offerId")

        // Accept a Credential Offer from EBSI CT
        //
        if (credOffer.credentialIssuer == KNOWN_ISSUER_EBSI_V3) {
            val authContext = walletSvc.createAuthorizationContext(ctx).withCredentialOffer(credOffer)
            val credJwt = walletSvc.getCredentialFromOffer(authContext, credOffer)
            return showCredentialDetails(call, ctx, credJwt.vcId)
        }

        // Accept a Credential Offer from Keycloak
        //
        val authContext = walletSvc.createAuthorizationContext(ctx).withCredentialOffer(credOffer)
        val authEndpointUrl = authContext.getIssuerMetadata().getAuthorizationEndpointUri()
        if (credOffer.isPreAuthorized) {
            val credJwt = walletSvc.getCredentialFromOffer(authContext, credOffer)
            call.respondRedirect(urlEncode("/wallet/${ctx.targetId}/credential/${credJwt.vcId}"))
        } else {
            val redirectUri = requireWalletConfig().redirectUri
            val authRequest = walletSvc.buildAuthorizationRequest(authContext, redirectUri = redirectUri)
            val authRequestUrl = authRequest.getAuthorizationRequestUrl(authEndpointUrl)
            log.info { "AuthRequestUrl: $authRequestUrl" }
            call.respondRedirect(authRequestUrl)
        }
    }

    suspend fun handleCredentialOfferDelete(call: RoutingCall, ctx: LoginContext, offerId: String) {
        walletSvc.deleteCredentialOffer(ctx, offerId)
        call.respondRedirect("/wallet/${ctx.targetId}/credential-offers")
    }

    suspend fun handleCredentialOfferDeleteAll(call: RoutingCall, ctx: LoginContext) {
        walletSvc.deleteCredentialOffers(ctx) { true }
        call.respondRedirect("/wallet/${ctx.targetId}/credential-offers")
    }

    suspend fun showCredentialOfferDetails(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId)
        val prettyJson = jsonPretty.encodeToString(credOffer)
        val model = walletModel(call, ctx).also {
            it["credOffer"] = prettyJson
            it["credOfferId"] = offerId
        }
        call.respond(
            FreeMarkerContent("wallet_cred_offer.ftl", model)
        )
    }

    suspend fun showCredentialOffers(call: RoutingCall, ctx: LoginContext) {
        val credOfferData = walletSvc.getCredentialOffers(ctx)
            .map { (k, v) ->
                listOf(
                    k.encodeURLPath(),
                    v.credentialIssuer,
                    v.filteredConfigurationIds.first(),
                    "${v.isPreAuthorized}"
                )
            }.toList()

        val model = walletModel(call, ctx).also {
            it["credentialOffers"] = credOfferData
            it["userDid"] = ctx.did
            it["credentialOfferEndpoint"] = "${requireEbsiConfig().baseUrl}/wallet/${ctx.targetId}"
        }

        call.respond(
            FreeMarkerContent("wallet_cred_offers.ftl", model)
        )
    }

    suspend fun handleCredentialDelete(call: RoutingCall, ctx: LoginContext, vcId: String) {
        walletSvc.deleteCredential(ctx, vcId)
        call.respondRedirect("/wallet/${ctx.targetId}/credentials")
    }

    suspend fun handleCredentialDeleteAll(call: RoutingCall, ctx: LoginContext) {
        walletSvc.deleteCredentials(ctx) { true }
        call.respondRedirect("/wallet/${ctx.targetId}/credentials")
    }

    suspend fun showCredentialDetails(call: RoutingCall, ctx: LoginContext, vcId: String) {

        val credJwt = walletSvc.getCredentialById(ctx, vcId) ?: error("No credential for: $vcId")
        val jsonObj = when (credJwt) {
            is W3CCredentialV11Jwt -> credJwt.toJson()
            is W3CCredentialSdV11Jwt -> buildJsonObject {
                credJwt.toJson().forEach { (k, v) -> put(k, v) }
                put("jti", JsonPrimitive(credJwt.vcId))
                put("disclosures", Json.decodeFromString(Json.encodeToString(credJwt.disclosures)))
            }
        }
        val prettyJson = jsonPretty.encodeToString(jsonObj)
        val model = walletModel(call, ctx).also {
            it["credId"] = credJwt.vcId
            it["credData"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("wallet_cred_detail.ftl", model)
        )
    }

    suspend fun showCredentials(call: RoutingCall, ctx: LoginContext) {

        fun abbreviatedDid(did: String) = when {
            did.length > 32 -> "${did.take(20)}...${did.substring(did.length - 12)}"
            else -> did
        }

        val credentialList = walletSvc.findCredentials(ctx) { true }.map { wc ->
            val credJwt = W3CCredentialJwt.fromEncoded(wc.document)
            when (credJwt) {
                is W3CCredentialV11Jwt -> {
                    val vc = credJwt.vc
                    listOf(credJwt.vcId.encodeURLPath(), abbreviatedDid(vc.issuer.id), "${vc.type}")
                }

                is W3CCredentialSdV11Jwt -> {
                    listOf(credJwt.vcId.encodeURLPath(), abbreviatedDid(credJwt.iss ?: "unknown"), credJwt.vct ?: "unknown")
                }
            }
        }
        val model = walletModel(call, ctx).also {
            it["credentials"] = credentialList
        }
        call.respond(
            FreeMarkerContent("wallet_credentials.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun handleAuthVPTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val httpParams = urlQueryToMap(call.request.uri)
        val authReq = AuthorizationRequest.fromHttpParameters(httpParams)
        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authReq)

        call.respondRedirect("/wallet/auth/flow/vp-token-consent?state=ask")
    }

    private suspend fun handleAuthVPTokenConsent(call: RoutingCall, ctx: LoginContext) {

        when (val state = call.parameters["state"]) {
            "ask" -> run {
                val authReq = ctx.getAttachment(AUTH_REQUEST_ATTACHMENT_KEY) as AuthorizationRequest
                val model = walletModel(call, ctx).also {
                    it["dcqlQuery"] = jsonPretty.encodeToString(authReq.dcqlQuery!!.toJsonObj())
                }
                call.respond(
                    FreeMarkerContent("holder_vp_ask.ftl", model)
                )
            }

            "accept" -> run {
                val authReq = ctx.removeAttachment(AUTH_REQUEST_ATTACHMENT_KEY) as AuthorizationRequest
                val authRes = walletSvc.authorizationSvc.handleVPTokenRequest(ctx, authReq)
                when (authReq.responseMode) {
                    "direct_post" -> run {
                        val res = http.post(authReq.responseUri!!) {
                            contentType(ContentType.Application.Json)
                            setBody(Json.encodeToString(authRes))
                        }

                        val resBody = res.bodyAsText()
                        if (res.status != HttpStatusCode.OK)
                            error(resBody)

                        val resObj = Json.decodeFromString<JsonObject>(resBody)
                        val redirectUri = resObj.getValue("redirect_uri").jsonPrimitive.content

                        call.respondRedirect(redirectUri)
                    }

                    else -> error("Unsupported response_mode: ${authReq.responseMode}")
                }
            }

            "reject" -> error("VPToken Request rejected")
            else -> error("Undefined flow state: $state")
        }
    }
}