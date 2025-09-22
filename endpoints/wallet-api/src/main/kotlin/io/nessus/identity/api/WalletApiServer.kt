package io.nessus.identity.api

import id.walt.webwallet.web.controllers.auth.getWalletId
import io.github.oshai.kotlinlogging.KotlinLogging
import io.github.smiley4.ktoropenapi.OpenApi
import io.github.smiley4.ktoropenapi.openApi
import io.github.smiley4.ktoropenapi.*
import io.github.smiley4.ktorswaggerui.swaggerUI
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.receive
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.util.getValue
import io.nessus.identity.types.CredentialOffer
import kotlin.uuid.ExperimentalUuidApi

class WalletApiServer {

    private val log = KotlinLogging.logger {}

    init {
        log.info { "Starting WalletApi Server ..." }
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val server = WalletApiServer().createServer()
            server.start(wait = true)
        }
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
                    description = "OID4VCI Wallet backend"
                }
                server {
                    url = "http://localhost:8080"
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

                // CredentialOffer Request ----------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credential-offer/request", {
                    summary = "Request a CredentialOffer"
                    description = "Request a CredentialOffer for the given parameters"
                    request {
                        queryParameter<String>("issuer") {
                            description = "The credential issuer URL"
                            required = true
                        }
                        queryParameter<String>("subject_did") {
                            description = "The requesting subject DID"
                            required = true
                        }
                        queryParameter<String>("credential_configuration_ids") {
                            description = "The requested credential configuration ids"
                            required = true
                        }
                    }
                    response {
                        HttpStatusCode.Created to {
                            description = "Stored CredentialOffer"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialOfferRequest(call) }

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
        return embeddedServer(Netty, port = 8080, module = Application::module)
    }

    private suspend fun handleCredentialOfferReceive(call: RoutingCall) {
        val walletId = call.parameters["walletId"]!!
        val credOffer = call.receive<CredentialOffer>()
        log.info { "Received CredentialOffer for $walletId: ${credOffer.toJson()}" }
        call.respondText("{}", status = HttpStatusCode.Created)
    }

    private suspend fun handleCredentialOfferRequest(call: RoutingCall) {
        val walletId = call.parameters["walletId"]!!
        val issuerUrl = call.parameters["issuer"]!!
        val subjectId = call.parameters["subject_id"]!!
        val configurationIds = call.parameters["credential_configuration_ids"]!!
        throw IllegalStateException("Not implemented")
    }
}
