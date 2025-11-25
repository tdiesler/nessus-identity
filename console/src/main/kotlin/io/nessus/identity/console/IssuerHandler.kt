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
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.http
import io.nessus.identity.types.CredentialConfiguration
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.Max
import io.nessus.identity.waltid.RegisterUserParams
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.keycloak.representations.idm.UserRepresentation
import kotlin.io.encoding.Base64


class IssuerHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuer = Max
    val issuerSvc = IssuerService.createKeycloak()
    val issuerMetadata get() = runBlocking { issuerSvc.getIssuerMetadata() }

    fun issuerModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        val issuerConfigUrl = issuerSvc.getIssuerMetadataUrl()
        val model = ctx?.let { BaseModel().withLoginContext(ctx) }
            ?: BaseModel().withLoginContext(call, UserRole.Holder)
        model["issuerUrl"] = issuerSvc.issuerBaseUrl
        model["issuerConfigUrl"] = issuerConfigUrl
        model["authConfigUrl"] = authConfigUrl
        return model
    }

    suspend fun showHome(call: RoutingCall) {
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

    suspend fun showCredentialConfig(call: RoutingCall, configId: String) {
        val credConfig = issuerMetadata.credentialConfigurationsSupported[configId] as CredentialConfiguration
        val prettyJson = jsonPretty.encodeToString(credConfig.toJsonObj())
        val model = issuerModel(call).also {
            it["configId"] = configId
            it["credConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_cred_config.ftl", model)
        )
    }

    suspend fun showCredentialOfferCreate(call: RoutingCall) {

        val configId = call.request.queryParameters["configId"] ?: error("No configId")
        val users = issuerSvc.getUsers().map { SubjectOption.fromUserRepresentation(it) }

        val model = issuerModel(call).also {
            it["configId"] = configId
            it["users"] = users
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offer_create.ftl", model)
        )
    }

    suspend fun handleCredentialOfferCreate(call: RoutingCall) {

        val params = call.receiveParameters()
        val configId = params["configId"] ?: error("No configId")
        val userId = params["userId"] ?: error("No userId")
        val preAuthorized = params["preAuthorized"].toBoolean()

        val usersMap = listOf(Alice, Bob, Max).associateBy { usr -> usr.email }
        val holder = usersMap[userId]

        val credOfferUri = issuerSvc.createCredentialOfferUri(issuer, configId, preAuthorized, holder)
        val credOfferQRCode = issuerSvc.createCredentialOfferUriQRCode(issuer, configId, preAuthorized, holder)

        val model = issuerModel(call).also {
            it["configId"] = configId
            it["holder"] = holder ?: User("Anonymous", "", "")
            it["credOfferUri"] = credOfferUri
            it["credOfferQRCode"] = Base64.encode(credOfferQRCode)
        }

        call.respond(
            FreeMarkerContent("issuer_cred_offer_send.ftl", model)
        )
    }

    suspend fun handleCredentialOfferSend(call: RoutingCall) {

        val params = call.receiveParameters()
        val credOfferUri = params["credOfferUri"] ?: error("No credOfferUri")

        val holderContext = requireLoginContext(call, UserRole.Holder)
        val targetId = holderContext.targetId

        val credOfferUriRes = http.get(credOfferUri) {}
        val credOffer = CredentialOffer.fromJson(credOfferUriRes.bodyAsText())

        val walletUrl = "${requireWalletConfig().baseUrl}/$targetId"
        val credOfferSendRes = http.get(walletUrl) {
            parameter("credential_offer", credOffer.toJson())
        }
        if (credOfferSendRes.status.value !in 200..202)
            error("Error sending credential Offer: ${credOfferSendRes.status.value} - ${credOfferSendRes.bodyAsText()}")

        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun showCredentialOffers(call: RoutingCall) {
        val supported = issuerMetadata.credentialConfigurationsSupported
        val model = issuerModel(call).also {
            it["configIds"] = supported.keys
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offers.ftl", model)
        )
    }

    suspend fun showUsers(call: RoutingCall) {
        val users = issuerSvc.getUsers().map { SubjectOption.fromUserRepresentation(it) }
        val model = issuerModel(call).also {
            it["users"] = users
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
