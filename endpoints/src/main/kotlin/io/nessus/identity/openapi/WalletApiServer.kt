package io.nessus.identity.openapi

import io.github.oshai.kotlinlogging.KotlinLogging
import io.github.smiley4.ktoropenapi.OpenApi
import io.github.smiley4.ktoropenapi.get
import io.github.smiley4.ktoropenapi.openApi
import io.github.smiley4.ktoropenapi.post
import io.github.smiley4.ktorswaggerui.swaggerUI
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.types.CredentialOffer
import kotlinx.serialization.json.Json

class WalletApiServer {

    companion object {

        val log = KotlinLogging.logger {}
        val versionInfo = getVersionInfo()

        val serverPort = 8080

        @JvmStatic
        fun main(args: Array<String>) {
            val server = WalletApiServer().createServer()
            server.start(wait = true)
        }
    }

    init {
        log.info { "Starting WalletApi Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
    }

    fun createServer(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        fun Application.module() {
            install(ContentNegotiation) {
                json()  // kotlinx.serialization JSON
            }

            install(OpenApi) {
                info {
                    title = "Wallet API"
                    version = "1.0.0"
                    description = "OID4VCI Wallet Backend"
                }
                server {
                    url = "http://localhost:$serverPort"
                    description = "Local dev server"
                }
            }

            routing {
                // OpenAPI/Swagger support routes
                //
                get("/", { hidden = true }) {
                    call.respondRedirect("/swagger")
                }
                route("/openapi.json") {
                    openApi()  // serves the generated spec
                }
                route("/swagger") {
                    swaggerUI("/openapi.json")
                }

                // CredentialOffer Receive ----------------------------------------------------------------------------
                //
                post("/wallets/{walletId}/credential-offer", {
                    summary = "Receive a CredentialOffer"
                    description = "Accepts and stores a CredentialOffer for the given wallet"
                    request {
                        body<CredentialOffer>()
                    }
                    response {
                        HttpStatusCode.Created to {
                            description = "Stored CredentialOffer"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialOfferReceive(call) }
            }
        }
        return embeddedServer(Netty, port = serverPort, module = Application::module)
    }

    private suspend fun handleCredentialOfferReceive(call: RoutingCall) {
        val walletId = call.parameters["walletId"]!!
        val credOffer = call.receive<CredentialOffer>()
        log.info { "Received CredentialOffer for $walletId: ${credOffer.toJson()}" }
        call.respondText("{}", status = HttpStatusCode.Created)
    }
}
