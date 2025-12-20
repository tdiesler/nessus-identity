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
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.ConsoleConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.HttpSessionStore.cookieName
import io.nessus.identity.console.HttpSessionStore.findLoginContext
import io.nessus.identity.console.HttpSessionStore.requireLoginContext
import io.nessus.identity.minisrv.IssuerApiHandler
import io.nessus.identity.minisrv.VerifierApiHandler
import io.nessus.identity.minisrv.WalletApiHandler
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.types.UserRole
import io.nessus.identity.utils.HttpStatusException
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class ConsoleServer(
    val config: ConsoleConfig,
    val issuerSvc: IssuerService,
    val walletSvc: WalletService,
    val verifierSvc: VerifierService,
) {
    val log = KotlinLogging.logger {}

    private val ebsiHandler: EBSIHandler
    private val walletHandler: WalletHandler
    private val issuerHandler: IssuerHandler
    private val verifierHandler: VerifierHandler

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            ConsoleServerBuilder()
                .withIssuerService(IssuerService.createKeycloak())
                .build().create().start(wait = true)
        }
    }

    init {
        val versionInfo = getVersionInfo()
        log.info { "Starting Console Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
        ebsiHandler = EBSIHandler(issuerSvc, walletSvc, verifierSvc)
        issuerHandler = IssuerHandler(issuerSvc)
        walletHandler = WalletHandler(walletSvc)
        verifierHandler = VerifierHandler(issuerSvc, walletSvc, verifierSvc)
        log.info { "Issuer Metadata: ${issuerSvc.getIssuerMetadataUrl()}" }
        log.info { "Issuer Authorization: ${issuerSvc.getAuthorizationMetadataUrl()}" }
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
                cookie<IssuerCookie>(cookieName(UserRole.Issuer)) {
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

                get("/") {
                    call.respondRedirect("/issuer")
                }

                get("/docs") {
                    call.respond(
                        FreeMarkerContent("docs_home.ftl", BaseModel())
                    )
                }

                route("/ebsi") {
                    get {
                        ebsiHandler.showHome(call)
                    }
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

                    // The Issuer's directed endpoints
                    //
                    route("/{targetId}") {
                        get("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER") {
                            IssuerApiHandler.handleIssuerMetadataRequest(call, issuerSvc)
                        }
                        if (issuerSvc is NativeIssuerService) {
                            val issuerApiHandler = IssuerApiHandler(issuerSvc)
                            post("/credential") {
                                issuerApiHandler.handleCredentialRequest(call)
                            }
                            post("/credential_deferred") {
                                issuerApiHandler.handleCredentialRequestDeferred(call)
                            }
                            get("/$WELL_KNOWN_OPENID_CONFIGURATION") {
                                issuerApiHandler.handleAuthorizationMetadataRequest(call)
                            }
                            get("/authorize") {
                                issuerApiHandler.handleAuthorize(call)
                            }
                            post("/direct_post") {
                                issuerApiHandler.handleDirectPost(call)
                            }
                            get("/jwks") {
                                issuerApiHandler.handleJwksRequest(call)
                            }
                            post("/token") {
                                issuerApiHandler.handleTokenRequest(call)
                            }
                        }
                    }
                }

                route("/wallet") {
                    get {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showHome(call, ctx)
                        }
                    }
                    get("/login") {
                        walletHandler.showLoginPage(call)
                    }
                    post("/login") {
                        walletHandler.handleLogin(call)
                    }
                    get("/logout") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.handleLogout(call, ctx)
                        }
                    }
                    get("/auth/callback/{targetId}") {
                        requireTargetContext(call, UserRole.Holder) { ctx ->
                            walletHandler.handleAuthCallback(call, ctx)
                        }
                    }
                    post("/auth/callback/{targetId}") {
                        error ("Not implemented ${call.request.uri}")
                    }
                    get("/auth-config") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showAuthConfig(call, ctx)
                        }
                    }
                    get("/credential-offers") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showCredentialOffers(call, ctx)
                        }
                    }
                    get("/credential-offer/{offerId}/accept") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.handleCredentialOfferAccept(call, ctx, offerId)
                        }
                    }
                    get("/credential-offer/{offerId}/delete") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.handleCredentialOfferDelete(call, ctx, offerId)
                        }
                    }
                    get("/credential-offer/delete-all") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.handleCredentialOfferDeleteAll(call, ctx)
                        }
                    }
                    get("/credential-offer/{offerId}/view") {
                        withHolderContextOrHome(call) { ctx ->
                            val offerId = call.parameters["offerId"] ?: error("No offerId")
                            walletHandler.showCredentialOfferDetails(call, ctx, offerId)
                        }
                    }
                    get("/credentials") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.showCredentials(call, ctx)
                        }
                    }
                    get("/credential/{vcId}") {
                        withHolderContextOrHome(call) { ctx ->
                            val vcId = call.parameters["vcId"] ?: error("No vcId")
                            walletHandler.showCredentialDetails(call, ctx, vcId)
                        }
                    }
                    get("/credential/{vcId}/delete") {
                        withHolderContextOrHome(call) { ctx ->
                            val vcId = call.parameters["vcId"] ?: error("No vcId")
                            walletHandler.handleCredentialDelete(call, ctx, vcId)
                        }
                    }
                    get("/credential/delete-all") {
                        withHolderContextOrHome(call) { ctx ->
                            walletHandler.handleCredentialDeleteAll(call, ctx)
                        }
                    }

                    // The Wallet's directed endpoints
                    //
                    route("/{targetId}") {
                        val walletApiHandler = WalletApiHandler(walletSvc)
                        get {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleCredentialOfferReceive(call, ctx)
                            }
                        }
                        get("/flow/{flowStep}") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                val flowStep = call.parameters["flowStep"] ?: error("No flowStep")
                                walletHandler.handleAuthFlow(call, ctx, flowStep)
                            }
                        }
                        get("/$WELL_KNOWN_OPENID_CONFIGURATION") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleAuthorize(call, ctx)
                            }
                        }
                        post("/direct_post") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleDirectPost(call, ctx)
                            }
                        }
                        get("/jwks") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleJwksRequest(call, ctx)
                            }
                        }
                        post("/token") {
                            requireTargetContext(call, UserRole.Holder) { ctx ->
                                walletApiHandler.handleTokenRequest(call, ctx)
                            }
                        }
                    }
                }

                route("/verifier") {
                    get {
                        withVerifierContextOrHome(call) { ctx ->
                            verifierHandler.showHome(call, ctx)
                        }
                    }
                    get("/login") {
                        verifierHandler.showLoginPage(call)
                    }
                    post("/login") {
                        verifierHandler.handleLogin(call)
                    }
                    get("/logout") {
                        withVerifierContextOrHome(call) { ctx ->
                            verifierHandler.handleLogout(call, ctx)
                        }
                    }
                    get("/auth-config") {
                        withVerifierContextOrHome(call) { ctx ->
                            verifierHandler.showAuthConfig(call, ctx)
                        }
                    }
                    get("/auth/callback/{targetId}") {
                        error ("Not implemented ${call.request.uri}")
                    }
                    post("/auth/callback/{targetId}") {
                        requireTargetContext(call, UserRole.Verifier) { ctx ->
                            verifierHandler.handleAuthCallback(call, ctx)
                        }
                    }
                    get("/presentation-request") {
                        withHolderContextOrHome(call) { ctx ->
                            verifierHandler.showPresentationRequest(call, ctx)
                        }
                    }
                    post("/presentation-request") {
                        withVerifierContextOrHome(call) { ctx ->
                            verifierHandler.handlePresentationRequest(call, ctx)
                        }
                    }
                    get("/presentation-response") {
                        withVerifierContextOrHome(call) { ctx ->
                            verifierHandler.showPresentationResponse(call, ctx)
                        }
                    }

                    // The Verifier's directed endpoints
                    //
                    route("/{targetId}") {
                        val verifierApiHandler = VerifierApiHandler(verifierSvc)
                        get("/$WELL_KNOWN_OPENID_CONFIGURATION") {
                            requireTargetContext(call, UserRole.Verifier) { ctx ->
                                verifierApiHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call, UserRole.Verifier) { ctx ->
                                verifierApiHandler.handleAuthorize(call, ctx)
                            }
                        }
                        post("/direct_post") {
                            requireTargetContext(call, UserRole.Verifier) { ctx ->
                                verifierApiHandler.handleDirectPost(call, ctx)
                            }
                        }
                        get("/jwks") {
                            requireTargetContext(call, UserRole.Verifier) { ctx ->
                                verifierApiHandler.handleJwksRequest(call, ctx)
                            }
                        }
                        post("/token") {
                            requireTargetContext(call, UserRole.Verifier) { ctx ->
                                verifierApiHandler.handleTokenRequest(call, ctx)
                            }
                        }
                    }
                }
            }
        }

        val config = requireConsoleConfig()
        return embeddedServer(Netty, host = config.host, port = config.port, module = Application::module)
    }

    private suspend fun requireTargetContext(call: RoutingCall, role: UserRole, block: suspend (LoginContext) -> Unit) {
        block(requireLoginContext(call, role))
    }

    private suspend fun withHolderContextOrHome(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val ctx = findLoginContext(call, UserRole.Holder)
        ctx?.let { ctx -> block(ctx) } ?: walletHandler.showHome(call, null)
    }

    private suspend fun withVerifierContextOrHome(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val ctx = findLoginContext(call, UserRole.Verifier)
        ctx?.let { ctx -> block(ctx) } ?: verifierHandler.showHome(call, null)
    }
}
