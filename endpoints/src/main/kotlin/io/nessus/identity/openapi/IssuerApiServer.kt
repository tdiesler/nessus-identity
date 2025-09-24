package io.nessus.identity.openapi

import io.github.oshai.kotlinlogging.KotlinLogging
import io.github.smiley4.ktoropenapi.OpenApi
import io.github.smiley4.ktoropenapi.get
import io.github.smiley4.ktoropenapi.openApi
import io.github.smiley4.ktorswaggerui.swaggerUI
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.IssuerServiceDraft17
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

class IssuerApiServer {

    var issuerSvc: IssuerServiceDraft17

    companion object {

        val log = KotlinLogging.logger {}
        val versionInfo = getVersionInfo()

        val serverPort = 8081

        @JvmStatic
        fun main(args: Array<String>) {
            val server = IssuerApiServer().create()
            server.start(wait = true)
        }
    }

    constructor() {
        log.info { "Starting IssuerAPI Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
        runBlocking {
            val ctx = OIDContext(LoginContext.login(Max).withDidInfo())
            issuerSvc = IssuerService.create(ctx)
        }
    }

    fun create(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        fun Application.module() {
            install(ContentNegotiation) {
                json()  // kotlinx.serialization JSON
            }

            install(OpenApi) {
                info {
                    title = "Issuer API"
                    version = "1.0.0"
                    description = "OID4VCI Issuer Backend"
                }
                server {
                    url = "http://localhost:${serverPort}"
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
                get("/issuer/credential-offer", {
                    summary = "Request a CredentialOffer"
                    description = "Request a CredentialOffer for the given parameters"
                    request {
                        queryParameter<String>("subject_id") {
                            description = "The requesting subject id"
                            required = true
                        }
                        queryParameter<List<String>>("credential_configuration_id") {
                            description = "The requested credential configuration id"
                            required = true
                        }
                    }
                    response {
                        HttpStatusCode.Created to {
                            description = "Created CredentialOffer"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialOfferRequest(call) }

            }
        }
        return embeddedServer(Netty, port = serverPort, module = Application::module)
    }

    private suspend fun handleCredentialOfferRequest(call: RoutingCall) {
        val subjectId = call.parameters["subject_id"]!!
        val configurationIds = call.parameters.getAll("credential_configuration_id")!!
        val credOffer = issuerSvc.createCredentialOffer(subId = subjectId, types = configurationIds)
        call.respond(HttpStatusCode.Created, credOffer)
    }
}
