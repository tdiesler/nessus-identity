package io.nessus.identity.console

import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.response.respond
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.User
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.keycloak.representations.idm.UserRepresentation
import kotlin.collections.firstOrNull


class IssuerHandler(val issuer: User) {

    val jsonPretty = Json { prettyPrint = true }

    val issuerMetadata get() = runBlocking { issuerSvc.getIssuerMetadata() }

    val issuerSvc = IssuerService.createKeycloak()

    fun issuerModel(): MutableMap<String, Any> {
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        val issuerConfigUrl = issuerSvc.getIssuerMetadataUrl()
        val versionInfo = getVersionInfo()
        return mutableMapOf(
            "issuerUrl" to issuerSvc.issuerBaseUrl,
            "issuerConfigUrl" to issuerConfigUrl,
            "authConfigUrl" to authConfigUrl,
            "versionInfo" to versionInfo,
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
        } else {
            model.put("subjects", issuerSvc.getRealmUsers().map { it ->
                SubjectOption.fromUserRepresentation(it)
            }.toList())
        }
        call.respond(
            FreeMarkerContent("issuer-cred-offer-create.ftl", model)
        )
        return credOffer
    }

    suspend fun handleIssuerCredentialOfferList(call: RoutingCall) {
        val supported = issuerMetadata.credentialConfigurationsSupported
        val credentialConfigurationIds = supported.keys
            // [TODO #294] Provide common VC data model
            // https://github.com/tdiesler/nessus-identity/issues/294
            .filter { it != "oid4vc_natural_person" }
            .toList()
        val model = issuerModel().also {
            it.put("credentialConfigurationIds", credentialConfigurationIds)
        }
        call.respond(
            FreeMarkerContent("issuer-cred-offers.ftl", model)
        )
    }
}

data class SubjectOption(
    val name: String,
    val email: String,
    val did: String,
) {
    companion object {
        fun fromUserRepresentation(it: UserRepresentation): SubjectOption {
            val did = it.attributes?.get("did")?.firstOrNull() ?: error("No Did")
            return SubjectOption("${it.firstName} ${it.lastName}", it.email, did)
        }
    }
}
