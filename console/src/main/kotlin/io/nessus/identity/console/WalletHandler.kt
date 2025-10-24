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
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.WalletAuthService
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestV10
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

    // [TODO #328] Associate WalletHandler state with LoginContext
    // https://github.com/tdiesler/nessus-identity/issues/328
    private val flowState = mutableMapOf<String, Any>()

    fun walletModel(call: RoutingCall): BaseModel {
        val model = BaseModel().withRoleAuth(call, UserRole.Holder)
        findLoginContext(call, UserRole.Holder)?.also {
            model["holderName"] = it.walletInfo.name
            model["holderDid"] = it.didInfo.did
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
        SessionsStore.newLoginContext(call, UserRole.Holder, loginParams)
        call.respondRedirect("/wallet")
    }

    suspend fun handleWalletLogout(call: RoutingCall) {
        SessionsStore.logout(call, UserRole.Holder)
        call.respondRedirect("/wallet")
    }

    suspend fun handleAuthorization(call: RoutingCall) {
        requireLoginContext(call, UserRole.Holder)
        when (val responseType = call.parameters["response_type"]) {
            "vp_token" -> handleAuthVPTokenRequest(call)
            else -> error("Unexpected response_type: $responseType")
        }
    }

    suspend fun handleAuthCallback(call: RoutingCall) {
        val authContext = flowState.remove("AuthorizationContext") as AuthorizationContext
        call.parameters["code"]?.also {
            authContext.withAuthCode(it)
            log.info { "AuthCode: $it" }
        } ?: error("No code")
        val vcJwt = walletSvc.credentialFromOfferInTime(authContext)
        call.respondRedirect("/wallet/credential/${vcJwt.vcId}")
    }

    suspend fun handleAuthFlow(call: RoutingCall, flowStep: String) {
        when (flowStep) {
            "vp-token-consent" -> handleAuthVPTokenConsent(call)
            else -> error("Unknown flow step: $flowStep")
        }
    }

    suspend fun handleCredentialOfferAccept(call: RoutingCall, offerId: String) {
        val ctx = requireLoginContext(call, UserRole.Holder)
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = ConfigProvider.requireWalletConfig().redirectUri
        val authContext = walletSvc.authContextForCredential(ctx, redirectUri, credOffer)
        flowState["AuthorizationContext"] = authContext
        val authRequestUrl = authContext.authRequestUrl
        log.info { "AuthRequestUrl: $authRequestUrl" }
        call.respondRedirect("$authRequestUrl")
    }

    suspend fun handleCredentialOfferAdd(call: RoutingCall) {
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleCredentialOfferDelete(call: RoutingCall, offerId: String) {
        val ctx = requireLoginContext(call, UserRole.Holder)
        when (offerId) {
            "__all__" -> walletSvc.deleteCredentialOffers(ctx) { true }
            else -> walletSvc.deleteCredentialOffer(ctx, offerId)
        }
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleCredentialDelete(call: RoutingCall, vcId: String) {
        val ctx = requireLoginContext(call, UserRole.Holder)
        when (vcId) {
            "__all__" -> walletSvc.deleteCredentials(ctx) { true }
            else -> walletSvc.deleteCredential(ctx, vcId)
        }
        call.respondRedirect("/wallet/credentials")
    }

    suspend fun showCredentialOfferDetails(call: RoutingCall, offerId: String) {

        val ctx = findLoginContext(call, UserRole.Holder)
            ?: return walletHomePage(call)

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

    suspend fun showCredentialOffers(call: RoutingCall) {

        val ctx = findLoginContext(call, UserRole.Holder)
            ?: return walletHomePage(call)

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

    suspend fun showCredentials(call: RoutingCall) {

        val ctx = findLoginContext(call, UserRole.Holder)
            ?: return walletHomePage(call)

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
            FreeMarkerContent("holder_creds.ftl", model)
        )
    }

    suspend fun showCredentialDetails(call: RoutingCall, vcId: String) {

        val ctx = findLoginContext(call, UserRole.Holder)
            ?: return walletHomePage(call)

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
            it["credObj"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("holder_cred.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun handleAuthVPTokenRequest(call: RoutingCall) {

        val httpParams = urlQueryToMap(call.request.uri)
        val authReq = AuthorizationRequestV10.fromHttpParameters(httpParams)
        flowState["VPTokenAuthorizationRequest"] = authReq

        call.respondRedirect("/wallet/auth/flow/vp-token-consent?state=ask")
    }

    private suspend fun handleAuthVPTokenConsent(call: RoutingCall) {

        when (val state = call.parameters["state"]) {
            "ask" -> run {
                val authReq = flowState["VPTokenAuthorizationRequest"] as AuthorizationRequestV10
                val model = walletModel(call).also {
                    it["dcqlQuery"] = jsonPretty.encodeToString(authReq.dcqlQuery!!.toJsonObj())
                }
                call.respond(
                    FreeMarkerContent("holder_vp_ask.ftl", model)
                )
            }
            "accept" -> run {
                val ctx = requireLoginContext(call, UserRole.Holder)
                val authReq = flowState.remove("VPTokenAuthorizationRequest") as AuthorizationRequestV10
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
            "deny" -> error("VPToken Request denied")
            else -> error("Undefined flow state: $state")
        }
    }
}