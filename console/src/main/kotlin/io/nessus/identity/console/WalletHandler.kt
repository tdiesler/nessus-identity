package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json

class WalletHandler(val holder: User) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc = WalletService.createKeycloak()

    lateinit var authContext: AuthorizationContext

    fun walletModel(ctx: LoginContext): MutableMap<String, Any> {
        val versionInfo = getVersionInfo()
        return mutableMapOf(
            "holderName" to ctx.walletInfo.name,
            "holderDid" to ctx.didInfo.did,
            "versionInfo" to versionInfo,
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
        val credOffers: Map<String, CredentialOfferV10> = walletSvc.getCredentialOffers()
        val credOfferData = credOffers.map { (k, v) ->
            listOf(k.encodeURLPath(), v.credentialIssuer, v.credentialConfigurationIds.first())
        }.toList()
        val model = walletModel(ctx).also {
            it.put("credentialOffers", credOfferData)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-offers.ftl", model)
        )
    }

    suspend fun handleWalletCredentialOfferAccept(call: RoutingCall, offerId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credOffer = walletSvc.getCredentialOffer(offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = ConfigProvider.requireWalletConfig().redirectUri
        authContext = walletSvc.authorizationContextFromOffer(ctx, redirectUri, credOffer)
        val authRequestUrl = authContext.authRequestUrl
        log.info { "AuthRequestUrl: $authRequestUrl" }
        call.respondRedirect("$authRequestUrl")
    }

    suspend fun handleOAuthCallback(call: RoutingCall) {
        call.parameters["code"]?.also {
            authContext.withAuthCode(it)
            log.info { "AuthCode: $it" }
        } ?: error("No code")
        val vcJwt = walletSvc.credentialFromOfferInTime(authContext)
        call.respondRedirect("/wallet/credential/${vcJwt.vcId}")
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
        fun abbreviatedDid(did: String) = when {
            did.length > 32 -> "${did.substring(0, 20)}...${did.substring(did.length - 12)}"
            else -> did
        }
        val credentialList = walletSvc.getCredentials(ctx).map { (vcId, vcJwt) ->
            when (vcJwt) {
                is VCDataV11Jwt -> {
                    val vc = vcJwt.vc
                    listOf(vcId.encodeURLPath(), abbreviatedDid(vc.issuer.id), "${vc.type}")
                }

                is VCDataSdV11Jwt -> {
                    listOf(vcId.encodeURLPath(), abbreviatedDid(vcJwt.iss ?: "unknown"), vcJwt.vct ?: "unknown")
                }
            }
        }
        val model = walletModel(ctx).also {
            it.put("credentialList", credentialList)
        }
        call.respond(
            FreeMarkerContent("wallet-credentials.ftl", model)
        )
    }

    suspend fun handleWalletCredentialDetails(call: RoutingCall, vcId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credObj = walletSvc.getCredential(ctx, vcId) ?: error("No credential for: $vcId")
        val prettyJson = jsonPretty.encodeToString(credObj)
        val model = walletModel(ctx).also {
            it.put("credObj", prettyJson)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-details.ftl", model)
        )
    }

    suspend fun handleWalletCredentialDelete(call: RoutingCall, vcId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        when (vcId) {
            "__all__" -> walletSvc.deleteCredentials(ctx) { true }
            else -> walletSvc.deleteCredential(ctx, vcId)
        }
        call.respondRedirect("/wallet/credentials")
    }
}