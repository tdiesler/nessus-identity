package io.nessus.identity.console

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.freemarker.*
import io.ktor.server.http.content.staticResources
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.Max
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import kotlin.uuid.ExperimentalUuidApi

@ExperimentalUuidApi
class ConsoleServer(val host: String = "0.0.0.0", val port: Int = 9000) {

    val log = KotlinLogging.logger {}

    val issuerHandler = IssuerHandler(Max)
    val walletHandler = WalletHandler(Alice)
    val verifierHandler = VerifierHandler(Bob)

    val versionInfo = getVersionInfo()

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            ConsoleServer().create().start(wait = true)
        }
    }

    init {
        log.info { "Starting Console Server ..." }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
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
            install(FreeMarker) {
                val classLoader = ConsoleServer::class.java.classLoader
                templateLoader = ClassTemplateLoader(classLoader, "templates")
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
                staticResources("/", "static")

                // Root -----------------------------------------------------------------------------------
                //
                get("/") {
                    call.respondRedirect("/wallet")
                }

                // Issuer ---------------------------------------------------------------------------------
                //
                get("/issuer") {
                    issuerHandler.handleIssuerHome(call)
                }
                get("/issuer/auth-config") {
                    issuerHandler.handleIssuerAuthConfig(call)
                }
                get("/issuer/issuer-config") {
                    issuerHandler.handleIssuerConfig(call)
                }
                get("/issuer/credential-offer") {
                    val ctype = call.request.queryParameters["ctype"]
                    if (ctype != null) {
                        issuerHandler.handleIssuerCredentialOffer(call, ctype) ?. also {
                            // [TODO #280] Issuer should use the wallet's cred offer endpoint
                            // https://github.com/tdiesler/nessus-identity/issues/280
                            walletHandler.walletSvc.addCredentialOffer(it)
                        }
                    } else {
                        issuerHandler.handleIssuerCredentialOfferList(call)
                    }
                }

                // Wallet ---------------------------------------------------------------------------------
                //
                get("/wallet") {
                    walletHandler.handleWalletHome(call)
                }
                get("/wallet/oauth/callback") {
                    walletHandler.handleOAuthCallback(call)
                }
                get("/wallet/credential-offers") {
                    walletHandler.handleWalletCredentialOffers(call)
                }
                get("/wallet/credential-offer/{offerId}/accept") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    walletHandler.handleWalletCredentialOfferAccept(call, offerId)
                }
                put("/wallet/credential-offer") {
                    walletHandler.handleWalletCredentialOfferAdd(call)
                }
                get("/wallet/credential-offer/{offerId}/delete") {
                    val offerId = call.parameters["offerId"] ?: error("No offerId")
                    walletHandler.handleWalletCredentialOfferDelete(call, offerId)
                }
                get("/wallet/credentials") {
                    walletHandler.handleWalletCredentials(call)
                }
                get("/wallet/credential/{credId}") {
                    val credId = call.parameters["credId"] ?: error("No credId")
                    walletHandler.handleWalletCredentialDetails(call, credId)
                }
                get("/wallet/credential/{credId}/delete") {
                    val credId = call.parameters["credId"] ?: error("No credId")
                    walletHandler.handleWalletCredentialDelete(call, credId)
                }

                // Verifier -------------------------------------------------------------------------------
                //
                get("/verifier") {
                    verifierHandler.handleVerifierHome(call)
                }
            }
        }
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }
}
