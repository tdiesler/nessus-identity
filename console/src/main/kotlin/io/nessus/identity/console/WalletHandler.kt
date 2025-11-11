package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext.Companion.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.WalletAuthService
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import kotlinx.serialization.json.*

class WalletHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc = WalletService.createKeycloak()
    val walletAuthSvc = WalletAuthService(walletSvc)

    fun walletModel(call: RoutingCall): BaseModel {
        val model = BaseModel().withLoginContext(call, UserRole.Holder)
        findLoginContext(call, UserRole.Holder)?.also {
            model["holderName"] = it.walletInfo.name
            model["holderDid"] = it.didInfo.did
            model["targetId"] = it.targetId
        }
        return model
    }

    suspend fun walletHomePage(call: RoutingCall) {
        val model = walletModel(call)
        call.respond(
            FreeMarkerContent("holder_home.ftl", model)
        )
    }

    suspend fun walletLoginPage(call: RoutingCall) {
        val model = walletModel(call)
        call.respond(
            FreeMarkerContent("holder_login.ftl", model)
        )
    }

    suspend fun handleWalletLogin(call: RoutingCall) {
        val params = call.receiveParameters()
        val email = params["email"] ?: error("No email")
        val password = params["password"] ?: error("No password")
        val loginParams = LoginParams(LoginType.EMAIL, email, password)
        SessionsStore.createLoginContext(call, UserRole.Holder, loginParams)
        call.respondRedirect("/wallet")
    }

    suspend fun handleWalletLogout(call: RoutingCall) {
        SessionsStore.logout(call, UserRole.Holder)
        call.respondRedirect("/wallet")
    }

    suspend fun handleAuthorization(call: RoutingCall, ctx: LoginContext) {
        when (val responseType = call.parameters["response_type"]) {
            "vp_token" -> handleAuthVPTokenRequest(call, ctx)
            else -> error("Unexpected response_type: $responseType")
        }
    }

    suspend fun handleAuthCallback(call: RoutingCall, ctx: LoginContext) {
        val authContext = ctx.getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) as AuthorizationContext
        call.parameters["code"]?.also {
            authContext.authCode = it
            log.info { "AuthCode: $it" }
        } ?: error("No code")
        val vcJwt = walletSvc.credentialFromOfferInTime(ctx)
        call.respondRedirect("/wallet/${ctx.targetId}/credential/${vcJwt.vcId}")
    }

    suspend fun handleAuthFlow(call: RoutingCall, ctx: LoginContext, flowStep: String) {
        when (flowStep) {
            "vp-token-consent" -> handleAuthVPTokenConsent(call, ctx)
            else -> error("Unknown flow step: $flowStep")
        }
    }

    suspend fun handleCredentialOffers(call: RoutingCall, ctx: LoginContext) {
        val credOfferData = walletSvc.getCredentialOffers(ctx)
            .map { (k, v) ->
                listOf(k.encodeURLPath(), v.credentialIssuer, v.filteredConfigurationIds.first())
            }.toList()
        val model = walletModel(call).also {
            it["credentialOffers"] = credOfferData
        }
        call.respond(
            FreeMarkerContent("holder_cred_offers.ftl", model)
        )
    }

    suspend fun handleCredentialOfferAccept(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = ConfigProvider.requireWalletConfig().redirectUri
        val authContext = walletSvc.authContextForCredential(ctx, redirectUri, credOffer)
        val authEndpointUrl = authContext.issuerMetadata.getAuthorizationAuthEndpoint()
        val authRequestUrl = authContext.authRequest.getAuthorizationRequestUrl(authEndpointUrl)

        log.info { "AuthRequestUrl: $authRequestUrl" }
        call.respondRedirect(authRequestUrl)
    }

    suspend fun handleCredentialOfferAdd(call: RoutingCall, targetId: String) {

        // An unsolicited call by the Issuer would likely not have a session cookie from which we can derive the target Holder wallet.
        // Instead, we expect to find a Holder LoginContext for the given targetId.
        val holderContexts = SessionsStore.loginContexts.values
            .filter { it.userRole == UserRole.Holder && it.targetId == targetId }
        if (holderContexts.isEmpty())
            error("No Holder LoginContext")
        if (holderContexts.size > 1)
            error("Multiple Holder LoginContexts")

        val credOffer = call.request.queryParameters["credential_offer"]
            ?.let { CredentialOfferV10.fromJson(it) }
            ?: error("No credential_offer")

        walletSvc.addCredentialOffer(holderContexts[0], credOffer)
        call.respondRedirect("/wallet/$targetId/credential-offers")
    }

    suspend fun handleCredentialOfferDelete(call: RoutingCall, ctx: LoginContext, offerId: String) {
        walletSvc.deleteCredentialOffer(ctx, offerId)
        call.respondRedirect("/wallet/${ctx.targetId}/credential-offers")
    }

    suspend fun handleCredentialOfferDeleteAll(call: RoutingCall, ctx: LoginContext) {
        walletSvc.deleteCredentialOffers(ctx) { true }
        call.respondRedirect("/wallet/${ctx.targetId}/credential-offers")
    }

    suspend fun handleCredentialOfferDetails(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId)
        val prettyJson = jsonPretty.encodeToString(credOffer)
        val model = walletModel(call).also {
            it["credOffer"] = prettyJson
            it["credOfferId"] = offerId
        }
        call.respond(
            FreeMarkerContent("holder_cred_offer.ftl", model)
        )
    }

    suspend fun handleCredentials(call: RoutingCall, ctx: LoginContext) {

        fun abbreviatedDid(did: String) = when {
            did.length > 32 -> "${did.take(20)}...${did.substring(did.length - 12)}"
            else -> did
        }

        val credentialList = walletSvc.findCredentials(ctx) { true }.map { wc ->
            val vcJwt = VCDataJwt.fromEncoded(wc.document)
            when (vcJwt) {
                is VCDataV11Jwt -> {
                    val vc = vcJwt.vc
                    listOf(vcJwt.vcId.encodeURLPath(), abbreviatedDid(vc.issuer.id), "${vc.type}")
                }

                is VCDataSdV11Jwt -> {
                    listOf(vcJwt.vcId.encodeURLPath(), abbreviatedDid(vcJwt.iss ?: "unknown"), vcJwt.vct ?: "unknown")
                }
            }
        }
        val model = walletModel(call).also {
            it["credentials"] = credentialList
        }
        call.respond(
            FreeMarkerContent("holder_credentials.ftl", model)
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

    suspend fun handleCredentialDetails(call: RoutingCall, ctx: LoginContext, vcId: String) {

        val vcJwt = walletSvc.getCredentialById(ctx, vcId) ?: error("No credential for: $vcId")
        val jsonObj = when (vcJwt) {
            is VCDataV11Jwt -> vcJwt.toJson()
            is VCDataSdV11Jwt -> buildJsonObject {
                vcJwt.toJson().forEach { (k, v) -> put(k, v) }
                put("jti", JsonPrimitive(vcJwt.vcId))
                put("disclosures", Json.decodeFromString(Json.encodeToString(vcJwt.disclosures)))
            }
        }
        val prettyJson = jsonPretty.encodeToString(jsonObj)
        val model = walletModel(call).also {
            it["credId"] = vcJwt.vcId
            it["credData"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("holder_cred_detail.ftl", model)
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
                val model = walletModel(call).also {
                    it["dcqlQuery"] = jsonPretty.encodeToString(authReq.dcqlQuery!!.toJsonObj())
                }
                call.respond(
                    FreeMarkerContent("holder_vp_ask.ftl", model)
                )
            }
            "accept" -> run {
                val authReq = ctx.removeAttachment(AUTH_REQUEST_ATTACHMENT_KEY) as AuthorizationRequest
                val authRes = walletAuthSvc.handleVPTokenRequest(ctx, authReq)
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