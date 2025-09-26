package io.nessus.identity.console

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.call.body
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.freemarker.*
import io.ktor.server.http.content.staticResources
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.backend.IssuerApiClient
import io.nessus.identity.backend.WalletApiClient
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.service.http
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.Alice
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.event.Level

class ConsoleUIServer(val host: String = "0.0.0.0", val port: Int = 8010) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuer = IssuerApiClient()
    val issuerBaseUrl = "https://auth.localtest.me"
    val issuerRealmUrl = "$issuerBaseUrl/realms/oid4vci"
    val issuerConfigUrl = "$issuerRealmUrl/.well-known/openid-credential-issuer"

    val issuerMetadata get() = runBlocking {
        http.get(issuerConfigUrl).body<IssuerMetadataDraft17>()
    }

    val wallet = WalletApiClient()
    var holderCtx: LoginContext

    companion object {

        val versionInfo = getVersionInfo()

        @JvmStatic
        fun main(args: Array<String>) {
            ConsoleUIServer().create().start(wait = true)
        }
    }

    init {
        log.info { "Starting WalletUI Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
        runBlocking {
            holderCtx = LoginContext.login(Alice).withDidInfo()
        }
    }

    fun create(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        fun Application.module() {
            install(CallLogging) {
                level = Level.INFO
                format { call ->
                    val method = call.request.httpMethod.value
                    val uri = call.request.uri
                    val status = call.response.status()?.value
                    "HTTP $method - $uri - Status: $status"
                }
            }
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
            install(FreeMarker) {
                val classLoader = ConsoleUIServer::class.java.classLoader
                templateLoader = ClassTemplateLoader(classLoader, "templates")
            }
            install(Sessions) {
                cookie<CookieData>(CookieData.NAME) {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                }
            }
            install(StatusPages) {
                exception<HttpStatusException> { call, ex ->
                    log.error(ex) { "Unexpected response status: ${ex.status} ${ex.message}" }
                    call.respond(ex.status, ex.message)
                }
                exception<Throwable> { call, ex ->
                    log.error(ex) { "Unhandled exception" }
                    call.respond(HttpStatusCode.InternalServerError, ex.message ?: "Internal error")
                }
            }
            routing {
                staticResources("/", "static")

                // Issuer ---------------------------------------------------------------------------------
                //
                get("/") {
                   call.respondRedirect("/issuer")
                }
                get("/issuer") {
                    handleIssuerHome(call)
                }
                get("/issuer/auth-config") {
                    handleIssuerAuthConfig(call)
                }
                get("/issuer/issuer-config") {
                    handleIssuerConfig(call)
                }
                get("/issuer/credential-offer") {
                    handleIssuerCredentialOffer(call)
                }

                // Wallet ---------------------------------------------------------------------------------
                //
                get("/wallet") {
                    handleWalletHome(call, holderCtx)
                }
                get("/wallet/credential-offers") {
                    handleWalletCredentialOffers(call, holderCtx)
                }
                get("/wallet/credential-offer/{offerId}/accept") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    handleWalletCredentialOfferAccept(call, holderCtx, offerId)
                }
                put("/wallet/credential-offer") {
                    handleWalletCredentialOfferAdd(call, holderCtx)
                }
                get("/wallet/credential-offer/{offerId}/delete") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    handleWalletCredentialOfferDelete(call, holderCtx, offerId)
                }
                get("/wallet/credentials") {
                    handleWalletCredentials(call, holderCtx)
                }
                get("/wallet/credential/{credId}") {
                    val credId = call.parameters["credId"] ?: error("No credId")
                    handleWalletCredentialDetails(call, holderCtx, credId)
                }

                // Verifier -------------------------------------------------------------------------------
                //
                get("/verifier") {
                    handleVerifierHome(call)
                }
            }
        }
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    // Issuer --------------------------------------------------------------------------------------------------------------------------------------------------
    //

    private fun issuerModel(): MutableMap<String, Any> {
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        return mutableMapOf(
            "issuerBaseUrl" to issuerBaseUrl,
            "issuerConfigUrl" to issuerConfigUrl,
            "authConfigUrl" to authConfigUrl,
        )
    }

    private suspend fun handleIssuerHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("issuer-home.ftl", issuerModel())
        )
    }

    private suspend fun handleIssuerAuthConfig(call: RoutingCall) {
        val authConfig = issuerMetadata.getAuthorizationMetadata()
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val model = issuerModel().also {
            it.put("authConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("auth-config.ftl", model)
        )
    }

    private suspend fun handleIssuerConfig(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel().also {
            it.put("issuerConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer-config.ftl", model)
        )
    }

    private suspend fun handleIssuerCredentialOffer(call: RoutingCall) {
        val ctype = call.request.queryParameters["ctype"]
        val subjectId = call.request.queryParameters["subjectId"]
        if (ctype != null) {
            val model = issuerModel().also {
                it.put("ctype", ctype)
            }
            if (subjectId != null) {
                val credOffer = issuer.createCredentialOffer(subjectId, listOf(ctype))
                val prettyJson = jsonPretty.encodeToString(credOffer)
                model.put("subjectId", subjectId)
                model.put("credentialOffer", prettyJson)
            }
            call.respond(
                FreeMarkerContent("issuer-cred-offer-create.ftl", model)
            )
        } else {
            val credentialConfigurationIds = issuerMetadata.credentialConfigurationsSupported.keys.toList()
            val model = issuerModel().also {
                it.put("credentialConfigurationIds", credentialConfigurationIds)
            }
            call.respond(
                FreeMarkerContent("issuer-cred-offers.ftl", model)
            )
        }
    }

    // Wallet --------------------------------------------------------------------------------------------------------------------------------------------------
    //

    private fun walletModel(ctx: LoginContext): MutableMap<String, Any> {
        return mutableMapOf(
            "holderName" to ctx.walletInfo.name,
        )
    }

    private suspend fun handleWalletHome(call: RoutingCall, ctx: LoginContext) {
        val model = walletModel(ctx)
        call.respond(
            FreeMarkerContent("wallet-home.ftl", model)
        )
    }

    private suspend fun handleWalletCredentialOffers(call: RoutingCall, ctx: LoginContext) {
        val credOffers: Map<String, CredentialOfferDraft17> = wallet.getCredentialOffers(ctx)
        val credOfferPairs = credOffers.map { (k, v) -> Pair(k, v.credentialConfigurationIds.first()) }.toList()
        val model = walletModel(ctx).also {
            it.put("credentialOffers", credOfferPairs)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-offers.ftl", model)
        )
    }

    private suspend fun handleWalletCredentialOfferAccept(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credObj = wallet.acceptCredentialOffer(ctx, offerId)
        val credId = credObj.getValue("jti").jsonPrimitive.content
        call.respondRedirect("/wallet/credential/$credId")
    }

    private suspend fun handleWalletCredentialOfferAdd(call: RoutingCall, ctx: LoginContext) {
        call.respondRedirect("/wallet/credential-offers")
    }

    private suspend fun handleWalletCredentialOfferDelete(call: RoutingCall, ctx: LoginContext, offerId: String) {
        wallet.deleteCredentialOffer(ctx, offerId)
        call.respondRedirect("/wallet/credential-offers")
    }

    private suspend fun handleWalletCredentials(call: RoutingCall, ctx: LoginContext) {
        val credentialList = wallet.getCredentials(ctx).map { (jti, cred) ->
            val vc = cred.getValue("vc").jsonObject
            val issuer = vc.getValue("issuer").jsonPrimitive.content
            val ctypes = vc.getValue("type").jsonArray.map {it.jsonPrimitive.content }
            listOf(jti, issuer, "$ctypes")
        }
        val model = walletModel(ctx).also {
            it.put("credentialList", credentialList)
        }
        call.respond(
            FreeMarkerContent("wallet-credentials.ftl", model)
        )
    }

    private suspend fun handleWalletCredentialDetails(call: RoutingCall, ctx: LoginContext, credId: String) {
        val credObj = wallet.getCredential(ctx, credId) ?: error("No credential for: $credId")
        val prettyJson = jsonPretty.encodeToString(credObj)
        val model = walletModel(ctx).also {
            it.put("credObj", prettyJson)
        }
        call.respond(
            FreeMarkerContent("wallet-cred-details.ftl", model)
        )
    }

    // Verifier ------------------------------------------------------------------------------------------------------------------------------------------------
    //

    private suspend fun handleVerifierHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("verifier-home.ftl", issuerModel())
        )
    }
}
