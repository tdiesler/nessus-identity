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
import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.ConsoleConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.cookieName
import io.nessus.identity.console.SessionsStore.createLoginContext
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class ConsoleServer(val config: ConsoleConfig) {

    val log = KotlinLogging.logger {}

    val issuerHandler = IssuerHandler()
    val walletHandler = WalletHandler()
    val verifierHandler = VerifierHandler()

    val versionInfo = getVersionInfo()

    private var autoLoginComplete = !config.autoLogin

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val config = requireConsoleConfig()
            ConsoleServer(config).create().start(wait = true)
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
                    autoLogin(call)
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
                        val ctx = requireLoginContext(call, UserRole.Holder)
                        walletHandler.walletSvc.addCredentialOffer(ctx, it)
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
                    autoLogin(call)
                    walletHandler.walletHomePage(call)
                }
                // Issuer Callback to obtain Holder consent for Credential issuance
                get("/wallet/auth/callback") {
                    val ctx = requireLoginContext(call, UserRole.Holder)
                    walletHandler.handleAuthCallback(call, ctx)
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

                get("/wallet/auth") {
                    val ctx = requireLoginContext(call, UserRole.Holder)
                    walletHandler.handleAuthorization(call, ctx)
                }
                get("/wallet/auth/flow/{flowStep}") {
                    val ctx = requireLoginContext(call, UserRole.Holder)
                    val flowStep = call.parameters["flowStep"] ?: error("No flowStep")
                    walletHandler.handleAuthFlow(call, ctx, flowStep)
                }
                get("/wallet/{targetId}/credential-offers") {
                    withHolderContextOrHome(call) { ctx ->
                        walletHandler.handleCredentialOffers(call, ctx)
                    }
                }
                put("/wallet/{targetId}/credential-offer") {
                    withHolderContextOrHome(call) { ctx ->
                        walletHandler.handleCredentialOfferAdd(call, ctx)
                    }
                }
                get("/wallet/{targetId}/credential-offer/{offerId}/accept") {
                    withHolderContextOrHome(call) { ctx ->
                        val offerId = call.parameters["offerId"] ?: error("No offerId")
                        walletHandler.handleCredentialOfferAccept(call, ctx, offerId)
                    }
                }
                get("/wallet/{targetId}/credential-offer/{offerId}/delete") {
                    withHolderContextOrHome(call) { ctx ->
                        val offerId = call.parameters["offerId"] ?: error("No offerId")
                        walletHandler.handleCredentialOfferDelete(call, ctx, offerId)
                    }
                }
                get("/wallet/{targetId}/credential-offer/delete-all") {
                    withHolderContextOrHome(call) { ctx ->
                        walletHandler.handleCredentialOfferDeleteAll(call, ctx)
                    }
                }
                get("/wallet/{targetId}/credential-offer/{offerId}/view") {
                    withHolderContextOrHome(call) { ctx ->
                        val offerId = call.parameters["offerId"] ?: error("No offerId")
                        walletHandler.handleCredentialOfferDetails(call, ctx, offerId)
                    }
                }
                get("/wallet/{targetId}/credentials") {
                    withHolderContextOrHome(call) { ctx ->
                        walletHandler.handleCredentials(call, ctx)
                    }
                }
                get("/wallet/{targetId}/credential/{vcId}") {
                    withHolderContextOrHome(call) { ctx ->
                        val vcId = call.parameters["vcId"] ?: error("No vcId")
                        walletHandler.handleCredentialDetails(call, ctx, vcId)
                    }
                }
                get("/wallet/{targetId}/credential/{vcId}/delete") {
                    withHolderContextOrHome(call) { ctx ->
                        val vcId = call.parameters["vcId"] ?: error("No vcId")
                        walletHandler.handleCredentialDelete(call, ctx, vcId)
                    }
                }
                get("/wallet/{targetId}/credential/delete-all") {
                    withHolderContextOrHome(call) { ctx ->
                        walletHandler.handleCredentialDeleteAll(call, ctx)
                    }
                }

                // Verifier -------------------------------------------------------------------------------
                //
                get("/verifier") {
                    autoLogin(call)
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

                get("/verifier/callback") {
                    val ctx = requireLoginContext(call, UserRole.Verifier)
                    verifierHandler.handleVerifierCallback(call, ctx)
                }
                post("/verifier/callback") {
                    verifierHandler.handleVerifierDirectPost(call)
                }
                get("/verifier/presentation-request") {
                    verifierHandler.showPresentationRequestPage(call)
                }
                post("/verifier/presentation-request") {
                    verifierHandler.handlePresentationRequest(call)
                }
            }
        }

        val host = config.host
        val port = config.port
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    private suspend fun autoLogin(call: RoutingCall) {
        if (config.autoLogin && !autoLoginComplete) {
            createLoginContext(call, UserRole.Holder, Alice.toLoginParams())
            createLoginContext(call, UserRole.Verifier, Bob.toLoginParams())
            autoLoginComplete = true
        }
    }

    private suspend fun withHolderContextOrHome(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val targetId = call.parameters["targetId"] ?: error("No targetId")
        val ctx = findLoginContext(call, UserRole.Holder, targetId)
        ctx?.let { ctx -> block(ctx) } ?: walletHandler.walletHomePage(call)
    }
}
