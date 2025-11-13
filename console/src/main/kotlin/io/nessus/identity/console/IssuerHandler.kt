package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.http
import io.nessus.identity.types.CredentialConfiguration
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.RegisterUserParams
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.keycloak.representations.idm.UserRepresentation


class IssuerHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()
    val issuerMetadata get() = runBlocking { issuerSvc.getIssuerMetadata() }

    fun issuerModel(call: RoutingCall): BaseModel {
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        val issuerConfigUrl = issuerSvc.getIssuerMetadataUrl()
        val model = BaseModel()
            .withLoginContext(call, UserRole.Holder)
            .also {
                it["issuerUrl"] = issuerSvc.issuerBaseUrl
                it["issuerConfigUrl"] = issuerConfigUrl
                it["authConfigUrl"] = authConfigUrl
            }
        return model
    }

    suspend fun issuerHomePage(call: RoutingCall) {
        val model = issuerModel(call)
        call.respond(
            FreeMarkerContent("issuer_home.ftl", model)
        )
    }

    suspend fun showAuthConfig(call: RoutingCall) {
        val authConfig = issuerMetadata.getAuthorizationMetadata()
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val model = issuerModel(call).also {
            it["authConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("auth_config.ftl", model)
        )
    }

    suspend fun showIssuerConfig(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel(call).also {
            it["issuerConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_config.ftl", model)
        )
    }

    suspend fun showCredentialConfigForType(call: RoutingCall, ctype: String) {
        val credConfig = issuerMetadata.credentialConfigurationsSupported[ctype] as CredentialConfiguration
        val prettyJson = jsonPretty.encodeToString(credConfig.toJsonObj())
        val model = issuerModel(call).also {
            it["ctype"] = ctype
            it["credConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_cred_config.ftl", model)
        )
    }

    suspend fun handleCredentialOfferCreate(call: RoutingCall) {

        val ctype = call.request.queryParameters["ctype"] ?: error("No ctype")
        val holderContext = requireLoginContext(call, UserRole.Holder)
        val authToken = holderContext.authToken

        // Show a selection of possible Holder target wallets
        //
        val userInfo = widWalletService.authUserInfo(authToken) ?: error("No UserInfo")
        val model = issuerModel(call).also {
            it["ctype"] = ctype
            it["userInfo"] = userInfo
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offer_send.ftl", model)
        )
    }

    suspend fun handleCredentialOfferSend(call: RoutingCall) {

        val ctype = call.request.queryParameters["ctype"] ?: error("No ctype")
        val subjectId = call.request.queryParameters["subjectId"] ?: error("No subjectId")
        val holderContext = requireLoginContext(call, UserRole.Holder)
        val targetId = holderContext.targetId

        // Create the CredentialOffer and send it to the Holder's wallet endpoint
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        val credOffer = issuerSvc.createCredentialOfferNative(subjectId, listOf(ctype))

        val walletUrl = "${requireWalletConfig().baseUrl}/$targetId"
        val res = http.get("$walletUrl/credential-offer" ) {
            parameter("credential_offer", credOffer.toJson())
        }
        if (res.status.value != 200)
            error("Error sending credential Offer: ${res.status.value} - ${res.bodyAsText()}")

        call.respondRedirect("$walletUrl/credential-offers")
    }

    suspend fun showCredentialOffers(call: RoutingCall) {
        val supported = issuerMetadata.credentialConfigurationsSupported
        val model = issuerModel(call).also {
            it["credentialConfigurationIds"] = supported.keys
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offers.ftl", model)
        )
    }

    suspend fun showUsers(call: RoutingCall) {
        val users = issuerSvc.getUsers().map { SubjectOption.fromUserRepresentation(it) }
        val model = issuerModel(call).also {
            it["credentialUsers"] = users
        }
        call.respond(
            FreeMarkerContent("issuer_users.ftl", model)
        )
    }

    suspend fun showCreateUserPage(call: RoutingCall) {
        val model = issuerModel(call)
        call.respond(
            FreeMarkerContent("issuer_user_create.ftl", model)
        )
    }

    suspend fun handleUserCreate(call: RoutingCall) {
        val params = call.receiveParameters()
        val name = params["name"] ?: error("No name")
        val nameParts = name.split(" ")
        require(nameParts.size == 2) { "Expected first and last name" }
        val (firstName, lastName) = Pair(nameParts[0], nameParts[1])
        val email = params["email"] ?: error("No email")
        val username = firstName.lowercase()
        val password = params["password"] ?: error("No password")

        // Register in WaltId (immutable henceforth)
        val userParams = RegisterUserParams(LoginType.EMAIL, name, email, password)
        runCatching {
            widWalletService.authRegister(userParams)
        }.onFailure { ex ->
            if (ex.message?.contains("account with email $email already exists") == true) {
                log.error(ex) { }
            } else {
                throw ex
            }
        }

        // Create in Keycloak (mutable henceforth)
        issuerSvc.createUser(firstName, lastName, email, username, password)
        call.respondRedirect("/issuer/users")
    }

    suspend fun handleUserDelete(call: RoutingCall, userId: String) {
        issuerSvc.deleteUser(userId)
        call.respondRedirect("/issuer/users")
    }
}

data class SubjectOption(
    val id: String,
    val name: String,
    val email: String,
) {
    companion object {
        fun fromUserRepresentation(it: UserRepresentation): SubjectOption {
            return SubjectOption(it.id, "${it.firstName} ${it.lastName}", it.email)
        }
    }
}
