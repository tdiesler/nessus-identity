package io.nessus.identity.console

import io.ktor.server.freemarker.*
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.types.CredentialConfiguration
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.waltid.User
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.keycloak.representations.idm.UserRepresentation


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
            FreeMarkerContent("issuer_home.ftl", issuerModel())
        )
    }

    suspend fun handleIssuerAuthConfig(call: RoutingCall) {
        val authConfig = issuerMetadata.getAuthorizationMetadata()
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val model = issuerModel().also {
            it.put("authConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("auth_config.ftl", model)
        )
    }

    suspend fun handleIssuerConfig(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel().also {
            it.put("issuerConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer_config.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialConfig(call: RoutingCall, ctype: String) {
        val credConfig = issuerMetadata.credentialConfigurationsSupported[ctype] as CredentialConfiguration
        val prettyJson = jsonPretty.encodeToString(credConfig.toJsonObj())
        val model = issuerModel().also {
            it.put("ctype", ctype)
            it.put("credConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer_cred_config.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialOffer(call: RoutingCall, ctype: String): CredentialOfferV10? {
        val ctx = findOrCreateLoginContext(call, issuer)
        val model = issuerModel().also {
            it.put("ctype", ctype)
        }
        var credOffer: CredentialOfferV10? = null
        val subjectId = call.request.queryParameters["subjectId"]
        if (subjectId != null) {
            credOffer = issuerSvc.createCredentialOffer(ctx, subjectId, listOf(ctype))
            val prettyJson = jsonPretty.encodeToString(credOffer)
            model.put("subjectId", subjectId)
            model.put("credOffer", prettyJson)
        } else {
            model.put("subjects", issuerSvc.getCredentialUsers().map { it ->
                SubjectOption.fromUserRepresentation(it)
            }.toList())
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offer_create.ftl", model)
        )
        return credOffer
    }

    suspend fun handleIssuerCredentialOffers(call: RoutingCall) {
        val supported = issuerMetadata.credentialConfigurationsSupported
        val model = issuerModel().also {
            it.put("credentialConfigurationIds", supported.keys)
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offers.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialUsers(call: RoutingCall) {
        val users = issuerSvc.getCredentialUsers().map { SubjectOption.fromUserRepresentation(it) }
        val model = issuerModel().also {
            it.put("credentialUsers", users)
        }
        call.respond(
            FreeMarkerContent("issuer_cred_users.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialUserCreateGet(call: RoutingCall) {
        val model = issuerModel()
        call.respond(
            FreeMarkerContent("issuer_cred_user_create.ftl", model)
        )
    }

    suspend fun handleIssuerCredentialUserCreatePost(call: RoutingCall) {
        val params = call.receiveParameters()
        val firstName = params["firstName"] ?: error("No firstName")
        val lastName = params["lastName"] ?: error("No lastName")
        val email = params["email"] ?: error("No email")
        val username = params["username"] ?: error("No username")
        val password = params["password"] ?: error("No password")
        issuerSvc.createCredentialUser(firstName, lastName, email, username, password)
        call.respondRedirect("/issuer/credential-users")
    }

    suspend fun handleIssuerCredentialUserDelete(call: RoutingCall, userId: String) {
        issuerSvc.deleteCredentialUser(userId)
        call.respondRedirect("/issuer/credential-users")
    }
}

data class SubjectOption(
    val id: String,
    val name: String,
    val email: String,
) {
    companion object {
        fun fromUserRepresentation(it: UserRepresentation): SubjectOption {
            return SubjectOption(it.id,"${it.firstName} ${it.lastName}", it.email)
        }
    }
}
