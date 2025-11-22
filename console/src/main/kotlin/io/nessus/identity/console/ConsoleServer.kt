package io.nessus.identity.console

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.Application
import io.ktor.server.application.createApplicationPlugin
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
    val ebsiHandler = EBSIHandler()

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
            install(createApplicationPlugin("AutoLoginPlugin") {
                onCall { call ->
                    if (config.autoLogin && !autoLoginComplete) {
                        createLoginContext(call, UserRole.Holder, Alice.toLoginParams())
                        createLoginContext(call, UserRole.Verifier, Bob.toLoginParams())
                        autoLoginComplete = true
                    }
                }
            })

            routing {
                staticResources("/", "static")

                get("/") {
                    call.respondRedirect("/wallet")
                }

                get("/docs") {
                    call.respond(
                        FreeMarkerContent("docs_home.ftl", BaseModel())
                    )
                }

                route("/issuer") {
                    get {
                        issuerHandler.showHome(call)
                    }
                    get("/auth-config") {
                        issuerHandler.showAuthConfig(call)
                    }
                    get("/issuer-config") {
                        issuerHandler.showIssuerConfig(call)
                    }
                    get("/credential-config/{configId}") {
                        val configId = call.parameters["configId"] ?: error("No configId")
                        issuerHandler.showCredentialConfig(call, configId)
                    }
                    get("/credential-offers") {
                        issuerHandler.showCredentialOffers(call)
                    }
                    get("/credential-offer/create") {
                        issuerHandler.showCredentialOfferCreate(call)
                    }
                    post("/credential-offer/create") {
                        issuerHandler.handleCredentialOfferCreate(call)
                    }
                    post("/credential-offer/send") {
                        issuerHandler.handleCredentialOfferSend(call)
                    }
                    get("/users") {
                        issuerHandler.showUsers(call)
                    }
                    get("/user-create") {
                        issuerHandler.showCreateUserPage(call)
                    }
                    post("/user-create") {
                        issuerHandler.handleUserCreate(call)
                    }
                    get("/user-delete/{userId}") {
                        val userId = call.parameters["userId"] ?: error("No userId")
                        issuerHandler.handleUserDelete(call, userId)
                    }
                }

                route("/wallet") {
                    get {
                        walletHandler.showHome(call)
                    }
                    route("/auth") {
                        get {
                            val ctx = requireLoginContext(call, UserRole.Holder)
                            walletHandler.handleAuthorization(call, ctx)
                        }
                        route("/callback") {
                            get {
                                val ctx = requireLoginContext(call, UserRole.Holder)
                                walletHandler.handleAuthCallback(call, ctx)
                            }
                            get("/{targetId}") {
                                val targetId = call.parameters["targetId"]
                                val ctx = requireLoginContext(call, UserRole.Holder, targetId)
                                walletHandler.handleAuthCallback(call, ctx)
                            }
                        }
                        get("/flow/{flowStep}") {
                            val ctx = requireLoginContext(call, UserRole.Holder)
                            val flowStep = call.parameters["flowStep"] ?: error("No flowStep")
                            walletHandler.handleAuthFlow(call, ctx, flowStep)
                        }
                        route ("/{targetId}") {
                            route ("/authorize") {
                                get {
                                    error("Not implemented /auth/authorize")
                                }
                            }
                            route ("/direct_post") {
                                post {
                                    error("Not implemented /auth/direct_post")
                                }
                            }
                            route ("/jwks") {
                                get {
                                    error("Not implemented /auth/jwks")
                                }
                            }
                            route ("/token") {
                                get {
                                    error("Not implemented /auth/token")
                                }
                            }
                        }
                    }
                    get("/login") {
                        walletHandler.showLoginPage(call)
                    }
                    post("/login") {
                        walletHandler.handleLogin(call)
                    }
                    get("/logout") {
                        walletHandler.handleLogout(call)
                    }
                    get("/{targetId}") {
                        val targetId = call.parameters["targetId"] ?: error("No targetId")
                        walletHandler.handleCredentialOfferReceive(call, targetId)
                    }
                    get("/{targetId}/credential-offers") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showCredentialOffers(call, ctx)
                        }
                    }
                    get("/{targetId}/credential-offer/{offerId}/accept") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.handleCredentialOfferAccept(call, ctx, offerId)
                        }
                    }
                    get("/{targetId}/credential-offer/{offerId}/delete") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.handleCredentialOfferDelete(call, ctx, offerId)
                        }
                    }
                    get("/{targetId}/credential-offer/delete-all") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.handleCredentialOfferDeleteAll(call, ctx)
                        }
                    }
                    get("/{targetId}/credential-offer/{offerId}/view") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.showCredentialOfferDetails(call, ctx, offerId)
                        }
                    }
                    get("/{targetId}/credentials") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showCredentials(call, ctx)
                        }
                    }
                    get("/{targetId}/credential/{vcId}") {
                        withHolderContextOrHome(call) { ctx ->
                            val vcId = call.parameters["vcId"] ?: error("No vcId")
                            walletHandler.showCredentialDetails(call, ctx, vcId)
                        }
                    }
                    get("/{targetId}/credential/{vcId}/delete") {
                        withHolderContextOrHome(call) { ctx ->
                            val vcId = call.parameters["vcId"] ?: error("No vcId")
                            walletHandler.handleCredentialDelete(call, ctx, vcId)
                        }
                    }
                    get("/{targetId}/credential/delete-all") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.handleCredentialDeleteAll(call, ctx)
                        }
                    }
                }

                route("/verifier") {
                    get {
                        verifierHandler.showHome(call)
                    }
                    get("/login") {
                        verifierHandler.showLoginPage(call)
                    }
                    post("/login") {
                        verifierHandler.handleLogin(call)
                    }
                    get("/logout") {
                        verifierHandler.handleLogout(call)
                    }
                    get("/callback") {
                        val ctx = requireLoginContext(call, UserRole.Verifier)
                        verifierHandler.handleVerifierCallback(call, ctx)
                    }
                    post("/callback") {
                        verifierHandler.handleVerifierDirectPost(call)
                    }
                    get("/presentation-request") {
                        verifierHandler.showPresentationRequestPage(call)
                    }
                    post("/presentation-request") {
                        verifierHandler.handlePresentationRequest(call)
                    }
                }

                route("/ebsi") {
                    get {
                        ebsiHandler.showHome(call)
                    }
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
        ctx?.let { ctx -> block(ctx) } ?: walletHandler.showHome(call)
    }
}
