package io.nessus.identity.openapi.wallet

import io.github.oshai.kotlinlogging.KotlinLogging
import io.github.smiley4.ktoropenapi.OpenApi
import io.github.smiley4.ktoropenapi.delete
import io.github.smiley4.ktoropenapi.get
import io.github.smiley4.ktoropenapi.openApi
import io.github.smiley4.ktoropenapi.put
import io.github.smiley4.ktorswaggerui.swaggerUI
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.PlaywrightAuthCallbackHandler
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.slf4j.event.Level

class WalletApiServer(val host: String = "0.0.0.0", val port: Int = 8001) {

    companion object {

        val log = KotlinLogging.logger {}
        val versionInfo = getVersionInfo()

        @JvmStatic
        fun main(args: Array<String>) {
            WalletApiServer().create().start(wait = true)
        }
    }

    val issuerCtx get() = runBlocking { LoginContext.login(Max).withDidInfo() }
    val holderCtx get() = runBlocking { LoginContext.login(Alice).withDidInfo() }

    // WalletServiceKeycloak is stateful
    val walletSvc = WalletService.createKeycloak()

    init {
        log.info { "Starting WalletApi Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
    }

    fun create(): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        fun Application.module() {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
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

                // CredentialOffer ------------------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credential-offers", {
                    summary = "List CredentialOffers"
                    description = "List available CredentialOffers"
                    response {
                        HttpStatusCode.OK to {
                            description = "Available CredentialOffers"
                        }
                    }
                }) { handleCredentialOfferList(call) }

                get("/wallets/{walletId}/credential-offer/{offerId}/accept", {
                    summary = "Accept a CredentialOffer"
                    description = "Accept a CredentialOffer and fetch the associated Credential from the Issuer"
                    request {
                        queryParameter<String>("credential_offer_id") {
                            description = "The CredentialOffer Id"
                            required = true
                        }
                    }
                    response {
                        HttpStatusCode.Created to {
                            description = "The Verifiable Credential"
                        }
                    }
                }) {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    handleCredentialOfferAccept(call, holderCtx, offerId)
                }

                put("/wallets/{walletId}/credential-offer", {
                    summary = "Add a CredentialOffer"
                    description = "Add a CredentialOffer to the Wallet"
                    request {
                        queryParameter<String>("credential_offer") {
                            description = "The CredentialOffer"
                            required = true
                        }
                    }
                }) { handleCredentialOfferAdd(call) }

                delete("/wallets/{walletId}/credential-offer/{offerId}", {
                    summary = "Delete a CredentialOffer"
                    description = "Delete a CredentialOffer from the Wallet."
                    request {
                        queryParameter<String>("offerId") {
                            description = "The credential offer id"
                            required = true
                        }
                    }
                }) {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    handleCredentialOfferDelete(call, offerId)
                }

                // Credential ---------------------------------------------------------------------------------------------
                //
                get("/wallets/{walletId}/credentials", {
                    summary = "List Credentials"
                    description = "List available Credentials"
                    response {
                        HttpStatusCode.OK to {
                            description = "Available Credentials"
                        }
                    }
                }) {
                    val ctx = OIDContext(holderCtx)
                    handleCredentialsList(call, ctx)
                }

                get("/wallets/{walletId}/credential/{vcId}", {
                    summary = "Get a Credential"
                    description = "Get a Credential by Id"
                }) {
                    val ctx = holderCtx
                    val vcId = call.parameters["vcId"] ?: error("No vcId")
                    handleCredentialGet(call, ctx, vcId)
                }
            }
        }

        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun populateWithBootstrapData(issuerCtx: LoginContext, subjectId: String): String {
        val issuerSvc = IssuerService.createKeycloak()
        val credOffer = issuerSvc.createCredentialOffer(issuerCtx, subjectId, listOf("oid4vc_identity_credential"))
        return walletSvc.addCredentialOffer(credOffer)
    }

    private suspend fun handleCredentialOfferList(call: RoutingCall) {
        var credOffers = walletSvc.getCredentialOffers()
        if (credOffers.isEmpty()) {
            populateWithBootstrapData(issuerCtx, holderCtx.did)
            credOffers = walletSvc.getCredentialOffers()
        }
        call.respond(credOffers)
    }

    private suspend fun handleCredentialOfferAdd(call: RoutingCall) {
        val credOffer = call.parameters["credential_offer"]?.let {
            CredentialOfferV10.fromJson(it)
        } ?: error("No credential_offer")
        val credOfferId = walletSvc.addCredentialOffer(credOffer)
        call.respond(credOfferId)
    }

    private suspend fun handleCredentialOfferAccept(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credOffer = walletSvc.getCredentialOffer(offerId) ?: error("No credential_offer for: $offerId")

        val redirectUri = "urn:ietf:wg:oauth:2.0:oob"
        val authContext = walletSvc.authorizationContextFromOffer(ctx, redirectUri, credOffer)

        val callbackHandler = PlaywrightAuthCallbackHandler(Alice.username, Alice.password)
        val authCode = callbackHandler.getAuthCode(authContext.authRequestUrl)

        val vcJwt = walletSvc.credentialFromOfferInTime(authContext.withAuthCode(authCode))
        call.respond(vcJwt.toJson())
    }

    private suspend fun handleCredentialOfferDelete(call: RoutingCall, offerId: String) {
        walletSvc.deleteCredentialOffer(offerId)
        call.respond("{}")
    }

    private suspend fun handleCredentialsList(call: RoutingCall, ctx: LoginContext) {
        val resMap = walletSvc.getCredentials(ctx).mapValues { (_, v) -> v.toJson() }
        call.respond(resMap)
    }

    private suspend fun handleCredentialGet(call: RoutingCall, ctx: LoginContext, vcId: String) {
        val vcJwt = walletSvc.getCredential(ctx, vcId)
        if (vcJwt != null) {
            call.respond(vcJwt.toJson())
        } else {
            call.respond(HttpStatusCode.NotFound)
        }
    }
}
