package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class WalletHandler(val holder: User) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc = WalletService.createKeycloak()

    lateinit var authContext: AuthorizationContext

    fun walletModel(ctx: LoginContext): MutableMap<String, Any> {
        return mutableMapOf(
            "holderName" to ctx.walletInfo.name,
            "holderDid" to ctx.didInfo.did,
        )
    }

    suspend fun handleWalletHome(call: RoutingCall) {
        val ctx = findOrCreateLoginContext(call, holder)
        val model = walletModel(ctx)
        call.respond(
            FreeMarkerContent("wallet-home.ftl", model)
        )
    }

    suspend fun handleWalletCredentialOffers(call: RoutingCall) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credOffers: Map<String, CredentialOfferDraft17> = walletSvc.getCredentialOffers()
        val credOfferData = credOffers.map { (k, v) -> listOf(k, v.credentialIssuer, v.credentialConfigurationIds.first()) }.toList()
        val model = walletModel(ctx).also {
            it.put("credentialOffers", credOfferData)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-offers.ftl", model)
        )
    }

    suspend fun handleWalletCredentialOfferAccept(call: RoutingCall, offerId: String) {
        val ctx = OIDContext(findOrCreateLoginContext(call, holder))
        val credOffer = walletSvc.getCredentialOffer(offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = ConfigProvider.requireWalletConfig().redirectUri
        authContext = walletSvc.authorizationContextFromOffer(ctx, redirectUri, credOffer)
        val authRequestUrl = authContext.authRequestUrl
        log.info { "AuthRequestUrl: $authRequestUrl" }
        call.respondRedirect("$authRequestUrl")
    }

    suspend fun handleOAuthCallback(call: RoutingCall) {
        call.parameters["code"]?. also {
            authContext.withAuthCode(it)
            log.info { "AuthCode: $it" }
        } ?: error("No code")
        val vcJwt = walletSvc.credentialFromOfferInTime(authContext)
        call.respondRedirect("/wallet/credential/${vcJwt.jti}")
    }

    suspend fun handleWalletCredentialOfferAdd(call: RoutingCall) {
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleWalletCredentialOfferDelete(call: RoutingCall, offerId: String) {
        walletSvc.deleteCredentialOffer(offerId)
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleWalletCredentials(call: RoutingCall) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credentialList = walletSvc.getCredentials(ctx).map { (jti, vcJwt) ->
            val vc = vcJwt.vc
            listOf(jti, vc.issuer, "${vc.type}")
        }
        val model = walletModel(ctx).also {
            it.put("credentialList", credentialList)
        }
        call.respond(
            FreeMarkerContent("wallet-credentials.ftl", model)
        )
    }

    suspend fun handleWalletCredentialDetails(call: RoutingCall, credId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credObj = walletSvc.getCredential(ctx, credId) ?: error("No credential for: $credId")
        val prettyJson = jsonPretty.encodeToString(credObj)
        val model = walletModel(ctx).also {
            it.put("credObj", prettyJson)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-details.ftl", model)
        )
    }

    suspend fun handleWalletCredentialDelete(call: RoutingCall, credId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        walletSvc.deleteCredential(ctx, credId)
        call.respondRedirect("/wallet/credentials")
    }
}