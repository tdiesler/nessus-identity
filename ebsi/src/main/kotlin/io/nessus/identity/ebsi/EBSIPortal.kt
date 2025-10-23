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
import io.nessus.identity.config.DatabaseConfig
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.ebsi.SessionsStore.cookieName
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*
import org.slf4j.event.Level

class EBSIPortal {

    val log = KotlinLogging.logger {}
    val versionInfo = getVersionInfo()

    init {
        log.info { "Starting the Nessus EBSI Conformance Portal ..." }
        val ebsi = ConfigProvider.requireEbsiConfig()
        val waltid = ConfigProvider.requireWaltIdConfig()
        val db = ConfigProvider.requireDatabaseConfig()
        val redacted = DatabaseConfig(db.jdbcUrl, db.username, "******")
        log.info { "EBSI Config: ${Json.encodeToString(ebsi)}" }
        log.info { "ServicesConfig: ${Json.encodeToString(waltid)}" }
        log.info { "DatabaseConfig: ${Json.encodeToString(redacted)}" }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            EBSIPortal().create().start(wait = true)
        }
    }

    fun create(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {

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
                json(Json { ignoreUnknownKeys = true })
            }
            install(FreeMarker) {
                templateLoader = ClassTemplateLoader(this::class.java.classLoader, "templates")
            }
            install(Sessions) {
                cookie<CookieData>(cookieName(UserRole.Holder)) {
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

        val ebsiCfg = ConfigProvider.requireEbsiConfig()
        return embeddedServer(Netty, host = ebsiCfg.host, port = ebsiCfg.port, module = module())
    }

    suspend fun handleHome(call: RoutingCall) {
        val ebsiCfg = ConfigProvider.requireEbsiConfig()
        val waltidCfg = ConfigProvider.requireWaltIdConfig()
        val ctx = SessionsStore.getLoginContextFromSession(call)
        val model = mutableMapOf(
            "hasWalletId" to (ctx?.maybeWalletInfo?.name?.isNotBlank() ?: false),
            "hasDidKey" to (ctx?.maybeDidInfo?.did?.isNotBlank() ?: false),
            "walletName" to ctx?.maybeWalletInfo?.name,
            "did" to ctx?.maybeDidInfo?.did,
            "demoWalletUrl" to waltidCfg.demoWallet!!.baseUrl,
            "devWalletUrl" to waltidCfg.devWallet!!.baseUrl,
            "versionInfo" to versionInfo,
        )
        if (ctx?.hasWalletInfo == true) {
            model["targetId"] = ctx.targetId
            model["walletUri"] = "${ebsiCfg.baseUrl}/wallet/${ctx.targetId}"
            model["issuerUri"] = "${ebsiCfg.baseUrl}/issuer/${ctx.targetId}"
            model["authUri"] = "${ebsiCfg.baseUrl}/auth/${ctx.targetId}"
        }
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = model
            )
        )
    }
}
