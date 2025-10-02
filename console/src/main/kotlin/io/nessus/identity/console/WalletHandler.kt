package io.nessus.identity.console

import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.PlaywrightAuthCallbackHandler
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.collections.component1
import kotlin.collections.component2

class WalletHandler(val holder: User) {

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc = WalletService.createKeycloak()

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
        val authCallbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
        val credObj = walletSvc.credentialFromOfferInTime(ctx, credOffer, authCallbackHandler)
        val credId = credObj.getValue("jti").jsonPrimitive.content
        call.respondRedirect("/wallet/credential/$credId")
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
        val credentialList = walletSvc.getCredentials(ctx).map { (jti, cred) ->
            val vc = cred.getValue("vc").jsonObject
            val issuer = vc.getValue("issuer").jsonPrimitive.content
            val ctypes = vc.getValue("type").jsonArray.map { it.jsonPrimitive.content }
            listOf(jti, issuer, "$ctypes")
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