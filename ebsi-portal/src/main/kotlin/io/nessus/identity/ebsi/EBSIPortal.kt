package io.nessus.identity.ebsi

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.freemarker.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.redacted
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.getVersionInfo
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import java.io.File
import java.security.KeyStore

fun main() {
    val server = EBSIPortal().createServer()
    server.start(wait = true)
}

class EBSIPortal {

    val log = KotlinLogging.logger {}

    private val versionInfo = getVersionInfo()

    constructor() {
        log.info { "Starting the Nessus EBSI Conformance Portal ..." }
        val serverConfig = ConfigProvider.requireServerConfig()
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val databaseConfig = ConfigProvider.requireDatabaseConfig()
        log.info { "ServerConfig: ${Json.encodeToString(serverConfig)}" }
        log.info { "ServiceConfig: ${Json.encodeToString(serviceConfig)}" }
        log.info { "DatabaseConfig: ${Json.encodeToString(databaseConfig.redacted())}" }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
    }

    fun createServer(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {

        fun configure(): NettyApplicationEngine.Configuration.() -> Unit = {
            val srv = ConfigProvider.requireServerConfig()

            val tls = ConfigProvider.root.tls
            if (tls?.enabled == true) {
                val keystorePassword = tls.keystorePassword.toCharArray()
                val keyStore = KeyStore.getInstance("PKCS12").apply {
                    load(File(tls.keystoreFile).inputStream(), keystorePassword)
                }
                sslConnector(
                    keyStore, tls.keyAlias,
                    { keystorePassword }, // Must both match -passout
                    { keystorePassword }
                ) {
                    host = srv.host
                    port = srv.port
                }
            } else {
                connector {
                    host = srv.host
                    port = srv.port
                }
            }
        }

        fun module(): Application.() -> Unit = {
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
                json()
            }
            install(FreeMarker) {
                templateLoader = ClassTemplateLoader(this::class.java.classLoader, "templates")
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
                get("/") {
                    handleHome(call)
                }
                post("/login") {
                    LoginHandler.handleLogin(call)
                    call.respondRedirect("/")
                }
                get("/logout") {
                    LoginHandler.handleLogout(call)
                }
                route("/auth/{dstId}/{...}") {
                    handle {
                        val dstId = call.parameters["dstId"] ?: throw IllegalArgumentException("No dstId")
                        OAuthHandler.handleAuthRequests(call, dstId)
                    }
                }
                route("/issuer/{dstId}/{...}") {
                    handle {
                        val dstId = call.parameters["dstId"] ?: throw IllegalArgumentException("No dstId")
                        IssuanceHandler.handleIssuerRequests(call, dstId)
                    }
                }
                route("/wallet/{dstId}/{...}") {
                    handle {
                        val dstId = call.parameters["dstId"] ?: throw IllegalArgumentException("No dstId")
                        WalletHandler.handleWalletRequests(call, dstId)
                    }
                }
            }
        }

        return embeddedServer(Netty, configure = configure(), module = module())
    }

    suspend fun handleHome(call: RoutingCall) {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val ctx = SessionsStore.getLoginContextFromSession(call)
        val model = mutableMapOf(
            "hasWalletId" to (ctx?.maybeWalletInfo?.name?.isNotBlank() ?: false),
            "hasDidKey" to (ctx?.maybeDidInfo?.did?.isNotBlank() ?: false),
            "walletName" to ctx?.maybeWalletInfo?.name,
            "did" to ctx?.maybeDidInfo?.did,
            "demoWalletUrl" to serviceConfig.demoWalletUrl,
            "devWalletUrl" to serviceConfig.devWalletUrl,
            "versionInfo" to versionInfo,
        )
        if (ctx?.hasWalletInfo == true) {
            model["targetId"] = ctx.targetId
            model["walletUri"] = "${ConfigProvider.walletEndpointUri}/${ctx.targetId}"
            model["issuerUri"] = "${ConfigProvider.issuerEndpointUri}/${ctx.targetId}"
            model["authUri"] = "${ConfigProvider.authEndpointUri}/${ctx.targetId}"
        }
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = model
            )
        )
    }
}
