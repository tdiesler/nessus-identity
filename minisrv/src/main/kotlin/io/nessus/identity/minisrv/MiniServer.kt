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
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.minisrv.IssuerApiHandler.Companion.handleIssuerMetadataRequest
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class MiniServer(
    val issuerSvc: IssuerService,
    val walletSvc: WalletService,
    val verifierSvc: VerifierService,
    val sessionStore: SessionStore,
) {

    val log = KotlinLogging.logger {}

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val miniServer = MiniServerBuilder().build()
            miniServer.create().start(wait = true)
        }
    }

    init {
        val versionInfo = getVersionInfo()
        log.info { "OID4VCI Mini-Server" }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
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
            routing {
                route("/issuer") {
                    route("/{targetId}") {
                        get("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER") {
                            handleIssuerMetadataRequest(call, issuerSvc)
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
                    val walletApiHandler = WalletApiHandler(walletSvc)
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
                    val verifierApiHandler = VerifierApiHandler(verifierSvc)
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

        val config = requireConsoleConfig()
        return embeddedServer(Netty, host = config.host, port = config.port, module = Application::module)
    }

    private suspend fun requireTargetContext(call: RoutingCall, block: suspend (LoginContext) -> Unit) {
        val targetId = requireNotNull(call.parameters["targetId"]) { "No target path" }
        block(sessionStore.requireLoginContext(targetId))
    }
}
