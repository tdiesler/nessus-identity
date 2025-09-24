package io.nessus.identity.backend

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
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.request.httpMethod
import io.ktor.server.request.uri
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.PlaywrightAuthCallbackHandler
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.WalletServiceKeycloak
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import java.lang.IllegalStateException

class WalletApiServer(val host: String = "0.0.0.0", val port: Int = 7000) {

    var walletSvc: WalletServiceKeycloak

    companion object {

        val log = KotlinLogging.logger {}
        val versionInfo = getVersionInfo()

        val username = Alice.username
        val password = Alice.password

        @JvmStatic
        fun main(args: Array<String>) {
            WalletApiServer().create().start(wait = true)
        }
    }

    init {
        log.info { "Starting WalletApi Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
        runBlocking {
            val alice = OIDContext(LoginContext.login(Alice).withDidInfo())
            walletSvc = WalletService.createKeycloak(alice)

            populateWithBootstrapData(alice)
        }
    }

    fun create(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        fun Application.module() {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
            //install(CORS) {
            //    allowHost("localhost:9000", schemes = listOf("http"))
            //    allowHeader(HttpHeaders.ContentType)
            //    allowHeader(HttpHeaders.Accept)
            //    allowMethod(HttpMethod.Get)
            //    allowMethod(HttpMethod.Post)
            //    allowMethod(HttpMethod.Options)
            //}
            install(OpenApi) {
                info {
                    title = "Wallet API"
                    version = "1.0.0"
                    description = "OID4VCI Wallet Backend"
                }
                server {
                    url = "http://$host:$port"
                    description = "Local dev server"
                }
            }

            install(CallLogging) {
                level = Level.INFO
                format { call ->
                    val method = call.request.httpMethod.value
                    val uri = call.request.uri
                    val status = call.response.status()?.value
                    "HTTP $method - $uri - Status: $status"
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

                // CredentialOffer list ----------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credential-offers", {
                    summary = "List CredentialOffers"
                    description = "List available CredentialOffers"
                    response {
                        HttpStatusCode.OK to {
                            description = "Available CredentialOffers"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialOffersList(call) }

                // CredentialOffer Receive ----------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credential-offers/receive", {
                    summary = "Receive a CredentialOffer"
                    description = "Accept and store a CredentialOffer for the given wallet"
                    request {
                        queryParameter<String>("credential_offer") {
                            description = "The credential offer"
                            required = true
                        }
                    }
                    response {
                        HttpStatusCode.OK to {
                            description = "Stored CredentialOffer"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialOffersAdd(call) }

                // Credential Fetch -----------------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credentials/fetch", {
                    summary = "Fetch a Credential"
                    description = "Fetch a Credential from a given CredentialOffer"
                    request {
                        queryParameter<String>("credential_offer_id") {
                            description = "The credential offer id"
                            required = true
                        }
                    }
                    response {
                        HttpStatusCode.Created to {
                            description = "Stored Credential"
                        }
                        HttpStatusCode.BadRequest to {
                            description = "Invalid input"
                        }
                    }
                }) { handleCredentialsFetch(call) }
            }
        }
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun populateWithBootstrapData(alice: OIDContext) {
        val max = OIDContext(LoginContext.login(Max).withDidInfo())
        val issuerSvc = IssuerService.createKeycloak(max)

        val credOffer = issuerSvc.createCredentialOffer(alice.did, listOf("oid4vc_identity_credential"))
        walletSvc.addCredentialOffer(credOffer)
    }

    private suspend fun handleCredentialOffersList(call: RoutingCall) {
        val credOffers: List<CredentialOfferDraft17> = walletSvc.getCredentialOffers()
        call.respond(credOffers)
    }

    private suspend fun handleCredentialOffersAdd(call: RoutingCall) {
        val credOffer = call.parameters["credential_offer"]?.let {
            Json.decodeFromString<CredentialOfferDraft17>(it)
        } ?: throw IllegalStateException("No credential_offer")
        val credOfferId = walletSvc.addCredentialOffer(credOffer)
        call.respondText { credOfferId }
    }

    private suspend fun handleCredentialsFetch(call: RoutingCall) {
        val offerId = call.parameters["credential_offer_id"]!!
        val credOffer = walletSvc.getCredentialOfferById(offerId)
            ?: throw IllegalStateException("No credential_offer")
        val authCallbackHandler = PlaywrightAuthCallbackHandler(username, password)
        val credObj = walletSvc.credentialFromOfferInTime(credOffer, authCallbackHandler)
        call.respond(credObj)
    }
}
