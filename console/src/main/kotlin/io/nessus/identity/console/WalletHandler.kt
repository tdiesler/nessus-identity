package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

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
            FreeMarkerContent("wallet_home.ftl", model)
        )
    }

    suspend fun handleWalletOAuthCallback(call: RoutingCall) {
        call.parameters["code"]?.also {
            authContext.withAuthCode(it)
            log.info { "AuthCode: $it" }
        } ?: error("No code")
        val vcJwt = walletSvc.credentialFromOfferInTime(authContext)
        call.respondRedirect("/wallet/credential/${vcJwt.vcId}")
    }

    suspend fun handleWalletCredentialOffers(call: RoutingCall) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credOffers: Map<String, CredentialOfferV10> = walletSvc.getCredentialOffers()
        val credOfferData = credOffers.map { (k, v) ->
            listOf(k.encodeURLPath(), v.credentialIssuer, v.credentialConfigurationIds.first())
        }.toList()
        val model = walletModel(ctx).also {
            it["credentialOffers"] = credOfferData
        }
        call.respond(
            FreeMarkerContent("wallet_cred_offer_list.ftl", model)
        )
    }

    suspend fun handleWalletCredentialOfferAccept(call: RoutingCall, offerId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credOffer = walletSvc.getCredentialOffer(offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = ConfigProvider.requireWalletConfig().redirectUri
        authContext = walletSvc.authContextForCredential(ctx, redirectUri, credOffer)
        val authRequestUrl = authContext.authRequestUrl
        log.info { "AuthRequestUrl: $authRequestUrl" }
        call.respondRedirect("$authRequestUrl")
    }

    suspend fun handleWalletCredentialOfferAdd(call: RoutingCall) {
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleWalletCredentialOfferDelete(call: RoutingCall, offerId: String) {
        walletSvc.deleteCredentialOffer(offerId)
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleWalletCredentialOfferView(call: RoutingCall, offerId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
        val credOffer = walletSvc.getCredentialOffer(offerId)
        val prettyJson = jsonPretty.encodeToString(credOffer)
        val model = walletModel(ctx).also {
            it["credOffer"] = prettyJson
            it["credOfferId"] = offerId
        }
        call.respond(
            FreeMarkerContent("wallet_cred_offer.ftl", model)
        )
    }

    suspend fun handleWalletCredentials(call: RoutingCall) {
        val ctx = findOrCreateLoginContext(call, holder)
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
        val model = walletModel(ctx).also {
            it["credentialList"] = credentialList
        }
        call.respond(
            FreeMarkerContent("wallet_cred_list.ftl", model)
        )
    }

    suspend fun handleWalletCredentialDetails(call: RoutingCall, vcId: String) {
        val ctx = findOrCreateLoginContext(call, holder)
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
        val model = walletModel(ctx).also {
            it["credObj"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("wallet_cred.ftl", model)
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