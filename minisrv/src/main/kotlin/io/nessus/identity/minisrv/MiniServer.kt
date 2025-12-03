package io.nessus.identity.minisrv

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.ConsoleConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.minisrv.SessionsStore.cookieName
import io.nessus.identity.minisrv.SessionsStore.createLoginContext
import io.nessus.identity.minisrv.SessionsStore.findLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import io.nessus.identity.toLoginParams
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class MiniServer(val config: ConsoleConfig) {

    val log = KotlinLogging.logger {}

    private val autoLoginComplete = mutableMapOf<UserRole, Boolean>()

    private val issuerSvc: IssuerService
    private val walletSvc: WalletService
    private val verifierSvc: VerifierService
    private val issuerApiHandler: IssuerApiHandler
    private val walletApiHandler: WalletApiHandler
    private val verifierApiHandler: VerifierApiHandler

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val config = requireConsoleConfig()
            MiniServer(config).create().start(wait = true)
        }
    }

    init {
        val versionInfo = getVersionInfo()
        log.info { "OID4VCI Mini-Server" }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
        issuerSvc = IssuerService.createNative() as NativeIssuerService
        walletSvc = WalletService.createNative()
        verifierSvc = VerifierService.createNative()
        issuerApiHandler = IssuerApiHandler(issuerSvc)
        walletApiHandler = WalletApiHandler(walletSvc)
        verifierApiHandler = VerifierApiHandler(verifierSvc)
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
            install(createApplicationPlugin("AutoLoginPlugin") {
                onCall { call ->
                    if (!(autoLoginComplete[UserRole.Issuer] ?: false)) {
                        val adminUser = requireIssuerConfig().adminUser
                        createLoginContext(call, UserRole.Issuer, adminUser.toLoginParams())
                        autoLoginComplete[UserRole.Issuer] = true
                    }
                    if (!(autoLoginComplete[UserRole.Holder] ?: false)) {
                        val testUser = requireWalletConfig().testUser
                        createLoginContext(call, UserRole.Holder, testUser.toLoginParams())
                        autoLoginComplete[UserRole.Holder] = true
                    }
                    if (!(autoLoginComplete[UserRole.Verifier] ?: false)) {
                        val testUser = requireVerifierConfig().testUser
                        createLoginContext(call, UserRole.Verifier, testUser.toLoginParams())
                        autoLoginComplete[UserRole.Verifier] = true
                    }
                }
            })

            routing {
                route("/issuer") {
                    route("/{targetId}") {
                        get("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER") {
                            issuerApiHandler.handleIssuerMetadataRequest(call)
                        }
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

                route("/wallet") {
                    route("/{targetId}") {
                        get {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleCredentialOfferReceive(call, ctx)
                            }
                        }
                        get("/$WELL_KNOWN_OPENID_CONFIGURATION") {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleAuthorize(call, ctx)
                            }
                        }
                        post("/direct_post") {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleDirectPost(call, ctx)
                            }
                        }
                        get("/jwks") {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleJwksRequest(call, ctx)
                            }
                        }
                        post("/token") {
                            requireTargetContext(call) { ctx ->
                                walletApiHandler.handleTokenRequest(call, ctx)
                            }
                        }
                    }
                }

                route("/verifier") {
                    route("/{targetId}") {
                        get("/$WELL_KNOWN_OPENID_CONFIGURATION") {
                            requireTargetContext(call) { ctx ->
                                verifierApiHandler.handleAuthorizationMetadataRequest(call, ctx)
                            }
                        }
                        get("/authorize") {
                            requireTargetContext(call) { ctx ->
                                verifierApiHandler.handleAuthorize(call, ctx)
                            }
                        }
                        post("/direct_post") {
                            requireTargetContext(call) { ctx ->
                                verifierApiHandler.handleDirectPost(call, ctx)
                            }
                        }
                        get("/jwks") {
                            requireTargetContext(call) { ctx ->
                                verifierApiHandler.handleJwksRequest(call, ctx)
                            }
                        }
                        post("/token") {
                            requireTargetContext(call) { ctx ->
                                verifierApiHandler.handleTokenRequest(call, ctx)
                            }
                        }
                    }
                }
            }
        }

        val host = config.host
        val port = config.port
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    private suspend fun requireTargetContext(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val targetId = requireNotNull(call.parameters["targetId"]) { "No target path" }
        val ctx = findLoginContext(call, targetId)
        block(requireNotNull(ctx) { "No login context for: $targetId" })
    }
}
