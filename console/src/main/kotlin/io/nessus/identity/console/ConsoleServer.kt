package io.nessus.identity.console

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.freemarker.*
import io.ktor.server.http.content.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.cookieName
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.Json
import org.slf4j.event.Level

class ConsoleServer(val host: String = "0.0.0.0", val port: Int = 9000) {

    val log = KotlinLogging.logger {}

    val issuerHandler = IssuerHandler()
    val walletHandler = WalletHandler()
    val verifierHandler = VerifierHandler()

    val versionInfo = getVersionInfo()

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            ConsoleServer().create().start(wait = true)
        }
    }

    init {
        log.info { "Starting Console Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
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
                val classLoader = ConsoleServer::class.java.classLoader
                templateLoader = ClassTemplateLoader(classLoader, "templates")
            }
            install(Sessions) {
                cookie<IssuerCookie>(cookieName(UserRole.Issuer)) {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                }
                cookie<HolderCookie>(cookieName(UserRole.Holder)) {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                }
                cookie<VerifierCookie>(cookieName(UserRole.Verifier)) {
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

                // Root -----------------------------------------------------------------------------------
                //
                get("/") {
                    call.respondRedirect("/issuer")
                }

                // Issuer ---------------------------------------------------------------------------------
                //
                get("/issuer") {
                    issuerHandler.issuerHomePage(call)
                }
                get("/issuer/auth-config") {
                    issuerHandler.showAuthConfig(call)
                }
                get("/issuer/issuer-config") {
                    issuerHandler.showIssuerConfig(call)
                }
                get("/issuer/credential-config/{ctype}") {
                    val ctype = call.parameters["ctype"] ?: error("No ctype")
                    issuerHandler.showCredentialConfigForType(call, ctype)
                }
                get("/issuer/credential-offers") {
                    issuerHandler.showCredentialOffers(call)
                }
                get("/issuer/credential-offer") {
                    val ctype = call.request.queryParameters["ctype"] ?: error("No ctype")
                    issuerHandler.handleCredentialOfferSend(call, ctype)?.also {
                        // [TODO #280] Issuer should use the wallet's cred offer endpoint
                        // https://github.com/tdiesler/nessus-identity/issues/280
                        val holderContext = requireLoginContext(call, UserRole.Holder)
                        walletHandler.walletSvc.addCredentialOffer(holderContext, it)
                    }
                }
                get("/issuer/users") {
                    issuerHandler.showUsers(call)
                }
                get("/issuer/user-create") {
                    issuerHandler.showCreateUserPage(call)
                }
                post("/issuer/user-create") {
                    issuerHandler.handleUserCreate(call)
                }
                get("/issuer/user-delete/{userId}") {
                    val userId = call.parameters["userId"] ?: error("No userId")
                    issuerHandler.handleUserDelete(call, userId)
                }

                // Wallet ---------------------------------------------------------------------------------
                //
                get("/wallet") {
                    walletHandler.walletHomePage(call)
                }
                get("/wallet/login") {
                    walletHandler.walletLoginPage(call)
                }
                post("/wallet/login") {
                    walletHandler.handleWalletLogin(call)
                }
                get("/wallet/logout") {
                    walletHandler.handleWalletLogout(call)
                }

                get("/wallet/oauth/callback") {
                    walletHandler.walletOAuthCallback(call)
                }
                get("/wallet/credential-offers") {
                    walletHandler.showCredentialOffers(call)
                }
                get("/wallet/credential-offer/{offerId}/accept") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    walletHandler.handleCredentialOfferAccept(call, offerId)
                }
                put("/wallet/credential-offer") {
                    walletHandler.handleCredentialOfferAdd(call)
                }
                get("/wallet/credential-offer/{offerId}/delete") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    walletHandler.handleCredentialOfferDelete(call, offerId)
                }
                get("/wallet/credential-offer/{offerId}/view") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    walletHandler.showCredentialOfferDetails(call, offerId)
                }
                get("/wallet/credentials") {
                    walletHandler.showCredentials(call)
                }
                get("/wallet/credential/{vcId}") {
                    val vcId = call.parameters["vcId"] ?: error("No vcId")
                    walletHandler.showCredentialDetails(call, vcId)
                }
                get("/wallet/credential/{vcId}/delete") {
                    val vcId = call.parameters["vcId"] ?: error("No vcId")
                    walletHandler.handleCredentialDelete(call, vcId)
                }

                // Verifier -------------------------------------------------------------------------------
                //
                get("/verifier") {
                    verifierHandler.verifierHomePage(call)
                }
                get("/verifier/login") {
                    verifierHandler.verifierLoginPage(call)
                }
                post("/verifier/login") {
                    verifierHandler.handleVerifierLogin(call)
                }
                get("/verifier/logout") {
                    verifierHandler.handleVerifierLogout(call)
                }
                get("/verifier/presentation-request") {
                    verifierHandler.showPresentationRequestPage(call)
                }
                post("/verifier/presentation-request") {
                    verifierHandler.handlePresentationRequest(call)
                }
            }
        }
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }
}
