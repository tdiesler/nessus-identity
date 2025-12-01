package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.config.ConfigProvider.Bob
import io.nessus.identity.config.ConfigProvider.Max
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.User
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.IssuerServiceKeycloak
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequestDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.RegisterUserParams
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64


class IssuerHandler(val issuerSvc: IssuerService) : AuthHandler(issuerSvc.authorizationSvc) {

    override val endpointUri = issuerSvc.endpointUri
    
    suspend fun issuerModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val authServerUrl = when(val issuerMetadata = issuerSvc.getIssuerMetadata()) {
            is IssuerMetadataV0 -> { issuerMetadata.authorizationServers?.firstOrNull() }
            is IssuerMetadataDraft11 -> { issuerMetadata.authorizationServer }
        } ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        val issuerConfigUrl = issuerSvc.getIssuerMetadataUrl()
        val model = ctx?.let { BaseModel().withLoginContext(ctx) }
            ?: BaseModel().withLoginContext(call, UserRole.Holder)
        model["issuerUrl"] = endpointUri
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
        val issuerMetadata = issuerSvc.getIssuerMetadata()
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
        val issuerMetadata = issuerSvc.getIssuerMetadata()
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel(call).also {
            it["issuerConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_config.ftl", model)
        )
    }

    suspend fun handleNativeAuthorization(call: RoutingCall, ctx: LoginContext) {

        log.info { "Issuer receives Authorization Request: ${call.request.uri}" }
        val queryParams = urlQueryToMap(call.request.uri)
        queryParams.forEach { (k, v) -> log.info { "  $k=$v" } }

        val authRequestIn = AuthorizationRequestDraft11.fromHttpParameters(queryParams)
        val redirectUri = requireNotNull(authRequestIn.redirectUri) { "No redirect_uri" }
        val authRequestOut = issuerSvc.createIDTokenRequest(ctx, authRequestIn)
        return call.respondRedirect(authRequestOut.toRequestUrl(redirectUri))
    }

    suspend fun handleNativeCredentialRequest(call: RoutingCall, ctx: LoginContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequestDraft11>()
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = issuerSvc.getNativeCredentialFromRequest(ctx, credReq, accessTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleNativeCredentialRequestDeferred(call: RoutingCall, ctx: LoginContext) {

        val acceptanceToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val acceptanceTokenJwt = SignedJWT.parse(acceptanceToken)
        val credentialResponse = issuerSvc.getNativeCredentialFromAcceptanceToken(ctx, acceptanceTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleNativeDirectPost(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Issuer DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val redirectUrl = authorizationSvc.getIDTokenRedirectUrl(ctx, idTokenJwt)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    suspend fun handleNativeAuthorizationMetadataRequest(call: RoutingCall) {
        val payload = Json.encodeToString(issuerSvc.getAuthorizationMetadata())
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleNativeIssuerMetadataRequest(call: RoutingCall) {
        val issuerMetadata = issuerSvc.getIssuerMetadata()
        val payload = Json.encodeToString(issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    override suspend fun handleTokenRequest(call: RoutingCall, ctx: LoginContext) {
        val authContext = ctx.getAuthContext()
        when(val issuerMetadata = issuerSvc.getIssuerMetadata()) {
            is IssuerMetadataDraft11 -> {
                authContext.putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
            }
            is IssuerMetadataV0 -> {
                authContext.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
            }
        }
        super.handleTokenRequest(call, ctx)
    }

    suspend fun showCredentialConfig(call: RoutingCall, configId: String) {
        val issuerMetadata = issuerSvc.getIssuerMetadata()
        val credConfig = when(issuerMetadata) {
            is IssuerMetadataDraft11 -> {
                issuerMetadata.credentialsSupported.first { it.types!!.contains(configId) }
            }
            is IssuerMetadataV0 -> {
                requireNotNull(issuerMetadata.credentialConfigurationsSupported[configId])
            }
        }
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
        val users = issuerSvc.getUsers()
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
        val targetUser = usersMap[userId]

        val credOfferUri = issuerSvc.createCredentialOfferUri(configId, preAuthorized = preAuthorized, targetUser = targetUser)

        val model = issuerModel(call).also {
            it["configId"] = configId
            it["holder"] = targetUser ?: User("Anonymous", "", "", "")
            it["credOfferUri"] = credOfferUri
        }
        if (issuerSvc is IssuerServiceKeycloak) {
            val credOfferQRCode = issuerSvc.createCredentialOfferUriQRCode(configId, preAuthorized, targetUser)
            model["credOfferQRCode"] = Base64.encode(credOfferQRCode)
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
        val issuerMetadata = issuerSvc.getIssuerMetadata()
        val supported = when(issuerMetadata) {
            is IssuerMetadataV0 -> issuerMetadata.credentialConfigurationsSupported.keys
            is IssuerMetadataDraft11 -> issuerMetadata.credentialsSupported.
                map { it.types!!.first { ct -> ct !in listOf("VerifiableAttestation", "VerifiableCredential") }}
        }
        val model = issuerModel(call).also {
            it["configIds"] = supported
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offers.ftl", model)
        )
    }

    suspend fun showUsers(call: RoutingCall) {
        val users = issuerSvc.getUsers()
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

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {
        return issuerSvc.createCredentialOffer(configId, clientId, preAuthorized, userPin, targetUser)
    }

    // Private ---------------------------------------------------------------------------------------------------------

}