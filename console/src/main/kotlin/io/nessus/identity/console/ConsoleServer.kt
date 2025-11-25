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
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.ConsoleConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.cookieName
import io.nessus.identity.console.SessionsStore.createLoginContext
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class ConsoleServer(val config: ConsoleConfig) {

    val log = KotlinLogging.logger {}

    val ebsiHandler = EBSIHandler()
    val issuerHandler = IssuerHandler()
    val walletHandler = WalletHandler()
    val verifierHandler = VerifierHandler()

    val versionInfo = getVersionInfo()

    private val autoLoginComplete = mutableMapOf<UserRole, Boolean>()

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
                    if (config.autoLogin) {
                        val requestPath = call.request.path()
                        if (!(autoLoginComplete[UserRole.Holder] ?: false)) {
                            createLoginContext(call, UserRole.Holder, Alice.toLoginParams())
                            autoLoginComplete[UserRole.Holder] = true
                        }
                        if (requestPath.startsWith("/verifier") && !(autoLoginComplete[UserRole.Verifier] ?: false)) {
                            createLoginContext(call, UserRole.Verifier, Bob.toLoginParams())
                            autoLoginComplete[UserRole.Verifier] = true
                        }
                    }
                }
            })

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
                        requireTargetContext(call) { ctx ->
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
                        get {
                            requireTargetContext(call) { ctx ->
                                walletHandler.handleCredentialOfferReceive(call, ctx)
                            }
                        }
                        get("/.well-known/openid-configuration") {
                            requireTargetContext(call) { ctx ->
                                walletHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call) { ctx ->
                                walletHandler.handleAuthorization(call, ctx)
                            }
                        }
                        get("/direct_post") {
                            error ("Not implemented ${call.request.uri}")
                        }
                        get("/flow/{flowStep}") {
                            requireTargetContext(call) { ctx ->
                                val flowStep = call.parameters["flowStep"] ?: error("No flowStep")
                                walletHandler.handleAuthFlow(call, ctx, flowStep)
                            }
                        }
                        get("/jwks") {
                            error ("Not implemented ${call.request.uri}")
                        }
                        get("/token") {
                            error ("Not implemented ${call.request.uri}")
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
                        requireTargetContext(call) { ctx ->
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
                        get("/.well-known/openid-configuration") {
                            requireTargetContext(call) { ctx ->
                                verifierHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call) { ctx ->
                                verifierHandler.handleAuthorization(call, ctx)
                            }
                        }
                        post("/direct_post") {
                            requireTargetContext(call) { ctx ->
                                verifierHandler.handleDirectPost(call, ctx)
                            }
                        }
                        get("/jwks") {
                            requireTargetContext(call) { ctx ->
                                verifierHandler.handleJwksRequest(call, ctx)
                            }
                        }
                        get("/token") {
                            error ("Not implemented ${call.request.uri}")
                        }
                    }
                }
            }
        }

        val host = config.host
        val port = config.port
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    private suspend fun handleDirectPost(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

//        if (postParams["id_token"] != null) {
//            val ctx = requireLoginContext(call, UserRole.Holder)
//            return authHandler.handleDirectPost(call, ctx, postParams)
//        }
//        if (postParams["vp_token"] != null) {
//            val ctx = requireLoginContext(call, UserRole.Verifier)
//            return verifierHandler.handleDirectPost(call, ctx, postParams)
//        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    private suspend fun requireTargetContext(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val targetId = requireNotNull(call.parameters["targetId"]) { "No target path" }
        val ctx = findLoginContext(call, targetId)
        block(requireNotNull(ctx) { "No login context for: $targetId" })
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
