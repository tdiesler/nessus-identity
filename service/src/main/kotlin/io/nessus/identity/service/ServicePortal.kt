package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.redacted
import kotlinx.serialization.json.Json

fun main() {
    val server = ServicePortal().createServer()
    server.start(wait = true)
}

class ServicePortal {

    val log = KotlinLogging.logger {}

    constructor() {
        log.info { "Starting the Nessus Service Portal ..." }
        val serverConfig = ConfigProvider.requireServerConfig()
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val databaseConfig = ConfigProvider.requireDatabaseConfig()
        log.info { "ServerConfig: ${Json.encodeToString(serverConfig)}" }
        log.info { "ServiceConfig: ${Json.encodeToString(serviceConfig)}" }
        log.info { "DatabaseConfig: ${Json.encodeToString(databaseConfig.redacted())}" }
    }

    fun createServer(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {

        fun configure(): NettyApplicationEngine.Configuration.() -> Unit = {
            val srv = ConfigProvider.requireServerConfig()

            connector {
                host = srv.host
                port = srv.port
            }
        }

        fun module(): Application.() -> Unit = {
            install(ContentNegotiation) {
                json()
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
                    call.respondText("Hello, Ktor!")
                }
            }
        }

        return embeddedServer(Netty, configure = configure(), module = module())
    }
}
