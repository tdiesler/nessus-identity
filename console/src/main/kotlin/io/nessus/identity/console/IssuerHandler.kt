package io.nessus.identity.console

import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.response.respond
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.User
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

class IssuerHandler(val issuer: User) {

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()

    val issuerBaseUrl = ConfigProvider.requireIssuerConfig().baseUrl
    val issuerConfigUrl = "$issuerBaseUrl/.well-known/openid-credential-issuer"
    val issuerMetadata get() = runBlocking { issuerSvc.getIssuerMetadata() }

    fun issuerModel(): MutableMap<String, Any> {
        val issuerUrl = issuerBaseUrl.substringBefore("/realms")
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        return mutableMapOf(
            "issuerUrl" to issuerUrl,
            "issuerConfigUrl" to issuerConfigUrl,
            "authConfigUrl" to authConfigUrl,
        )
    }

    suspend fun handleIssuerHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("issuer-home.ftl", issuerModel())
        )
    }

    suspend fun handleIssuerAuthConfig(call: RoutingCall) {
        val authConfig = issuerMetadata.getAuthorizationMetadata()
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val model = issuerModel().also {
            it.put("authConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("auth-config.ftl", model)
        )
    }

    suspend fun handleIssuerConfig(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel().also {
            it.put("issuerConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer-config.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialOffer(call: RoutingCall, ctype: String): CredentialOfferDraft17? {
        val ctx = findOrCreateLoginContext(call, issuer)
        val model = issuerModel().also {
            it.put("ctype", ctype)
        }
        var credOffer: CredentialOfferDraft17? = null
        val subjectId = call.request.queryParameters["subjectId"]
        if (subjectId != null) {
            credOffer = issuerSvc.createCredentialOffer(ctx, subjectId, listOf(ctype))
            val prettyJson = jsonPretty.encodeToString(credOffer)
            model.put("subjectId", subjectId)
            model.put("credentialOffer", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer-cred-offer-create.ftl", model)
        )
        return credOffer
    }

    suspend fun handleIssuerCredentialOfferList(call: RoutingCall) {
        val credentialConfigurationIds = issuerMetadata.credentialConfigurationsSupported.keys.toList()
        val model = issuerModel().also {
            it.put("credentialConfigurationIds", credentialConfigurationIds)
        }
        call.respond(
            FreeMarkerContent("issuer-cred-offers.ftl", model)
        )
    }
}