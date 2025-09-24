package io.nessus.identity.webapp

import freemarker.cache.ClassTemplateLoader
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.call.body
import io.ktor.client.request.*
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
import io.nessus.identity.backend.IssuerApiClient
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.service.http
import io.nessus.identity.types.IssuerMetadataDraft17
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.slf4j.event.Level

class ConsoleUIServer(val host: String = "0.0.0.0", val port: Int = 8010) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerApi = IssuerApiClient()
    val issuerBaseUrl = "https://auth.localtest.me/realms/oid4vci"
    val issuerConfigUrl = "$issuerBaseUrl/.well-known/openid-credential-issuer"

    val issuerMetadata get() = runBlocking {
        http.get(issuerConfigUrl).body<IssuerMetadataDraft17>()
    }

    companion object {

        val versionInfo = getVersionInfo()

        @JvmStatic
        fun main(args: Array<String>) {
            ConsoleUIServer().create().start(wait = true)
        }
    }

    init {
        log.info { "Starting WalletUI Server ..." }
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
                val classLoader = ConsoleUIServer::class.java.classLoader
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
                get("/") {
                   call.respondRedirect("/issuer")
                }
                get("/issuer") {
                    handleIssuerHome(call)
                }
                get("/issuer/config") {
                    handleIssuerMetadata(call)
                }
                get("/issuer/credential-offer") {
                    handleIssuerCredentialOffer(call)
                }
                post("/issuer/credential-offer") {
                    handleIssuerCredentialOfferCreate(call)
                }

                get("/wallet") {
                    handleWalletHome(call)
                }

                get("/verifier") {
                    handleVerifierHome(call)
                }
            }
        }
        return embeddedServer(Netty, host = host, port = port, module = Application::module)
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private fun issuerModel(): MutableMap<String, Any> {
        return mutableMapOf(
            "issuerConfigUrl" to issuerConfigUrl,
        )
    }

    private suspend fun handleIssuerHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("issuer-home.ftl", issuerModel())
        )
    }

    private suspend fun handleIssuerCredentialOffer(call: RoutingCall) {
        val ctype = call.request.queryParameters["ctype"]
        if (ctype != null) {
            val model = issuerModel().also {
                it.put("ctype", ctype)
            }
            call.respond(
                FreeMarkerContent("issuer-cred-offer-create.ftl", model)
            )
        } else {
            val credentialConfigurationIds = issuerMetadata.credentialConfigurationsSupported.keys.toList()
            val model = issuerModel().also {
                it.put("credentialConfigurationIds", credentialConfigurationIds)
            }
            call.respond(
                FreeMarkerContent("issuer-cred-offer.ftl", model)
            )
        }
    }

    private suspend fun handleIssuerCredentialOfferCreate(call: RoutingCall) {
        val params = call.receiveParameters()
        val ctype = params["ctype"]!!
        val subjectId = params["subjectId"]!!
        val credOffer = issuerApi.createCredentialOffer(subjectId, listOf(ctype))
        val prettyJson = jsonPretty.encodeToString(credOffer)
        val model = issuerModel().also {
            it.put("ctype", ctype)
            it.put("subjectId", subjectId)
            it.put("credentialOffer", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer-cred-offer-create.ftl", model)
        )
    }

    private suspend fun handleIssuerMetadata(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel().also {
            it.put("issuerConfigJson", prettyJson)
        }
        call.respond(
            FreeMarkerContent("issuer-config.ftl", model)
        )
    }

    private suspend fun handleWalletHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("wallet-home.ftl", issuerModel())
        )
    }

    private suspend fun handleVerifierHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("verifier-home.ftl", issuerModel())
        )
    }
}
