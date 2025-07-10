package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import freemarker.cache.ClassTemplateLoader
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
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
import io.ktor.util.toMap
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.redacted
import io.nessus.identity.service.AuthService
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.FlowContext
import io.nessus.identity.service.FlowContext.Companion.requireCredentialExchange
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.toSignedJWT
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.JwtCredential
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.slf4j.event.Level
import java.io.File
import java.security.KeyStore
import kotlin.text.toCharArray

fun main() {
    val server = EBSIPortal().createServer()
    server.start(wait = true)
}

class EBSIPortal {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessions = mutableMapOf<String, LoginContext>()

    constructor() {
        log.info { "Starting the Nessus EBSI Conformance Portal ..." }
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
                    handleLogin(call)
                    call.respondRedirect("/")
                }
                get("/logout") {
                    getLoginContextFromSession(call)?.also { it.close() }
                    call.sessions.clear(CookieData.NAME)
                    call.respondRedirect("/")
                    sessions.clear()
                }
                route("/auth/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleAuthRequests(call, subId)
                    }
                }
                route("/wallet/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleWalletRequests(call, subId)
                    }
                }
                route("/issuer/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleIssuerRequests(call, subId)
                    }
                }
            }
        }

        return embeddedServer(Netty, configure = configure(), module = module())
    }

    suspend fun handleHome(call: RoutingCall) {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val ctx = getLoginContextFromSession(call)
        val model = mutableMapOf(
            "hasWalletId" to (ctx?.maybeWalletInfo?.name?.isNotBlank() ?: false),
            "hasDidKey" to (ctx?.maybeDidInfo?.did?.isNotBlank() ?: false),
            "walletName" to ctx?.maybeWalletInfo?.name,
            "did" to ctx?.maybeDidInfo?.did,
            "demoWalletUrl" to serviceConfig.demoWalletUrl,
            "devWalletUrl" to serviceConfig.devWalletUrl,
        )
        if (ctx?.hasWalletInfo == true) {
            model["subjectId"] = ctx.subjectId
            model["walletUri"] = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
            model["issuerUri"] = "${ConfigProvider.issuerEndpointUri}/${ctx.subjectId}"
            model["authUri"] = "${ConfigProvider.authEndpointUri}/${ctx.subjectId}"
        }
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = model
            )
        )
    }

    // Handle Login ----------------------------------------------------------------------------------------------------
    //
    suspend fun handleLogin(call: RoutingCall) {

        val params = call.receiveParameters()
        val email = params["email"]
        val password = params["password"]

        if (email.isNullOrBlank() || password.isNullOrBlank())
            return call.respond(HttpStatusCode.BadRequest, "Missing email or password")

        runBlocking {
            val ctx = widWalletSvc.loginWithWallet(LoginParams(LoginType.EMAIL, email, password))
            widWalletSvc.findDidByPrefix(ctx,"did:key")?.also {
                ctx.didInfo = it
            }
            val dat = CookieData(ctx.walletInfo.id, ctx.maybeDidInfo?.did)
            setCookieDataInSession(call, dat)
        }
    }

    // Handle Authorization Requests -----------------------------------------------------------------------------------
    //
    suspend fun handleAuthRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Authorization $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(subId)

        if (path.endsWith(".well-known/openid-configuration")) {
            return handleAuthorizationMetadataRequest(call, ctx)
        }

        // authorize
        // 
        if (path == "/auth/$subId/authorize") {
            val cex = FlowContext(ctx)
            return handleAuthorizationRequest(call, cex)
        }

        // direct_post
        //
        if (path == "/auth/$subId/direct_post") {
            val cex = requireCredentialExchange(subId)
            return handleAuthDirectPost(call, cex)
        }

        // jwks
        //
        if (path == "/auth/$subId/jwks") {
            return handleAuthJwksRequest(call, ctx)
        }

        // token
        //
        if (path == "/auth/$subId/token") {
            return handleAuthTokenRequest(call, subId)
        }

        // Callback as part of the Authorization Request
        //
        if (path == "/auth/$subId") {
            val responseType = queryParams["response_type"]
            if (responseType == "id_token") {
                val cex = requireCredentialExchange(subId)
                return handleIDTokenRequest(call, cex)
            }
            if (responseType == "vp_token") {
                val cex = requireCredentialExchange(subId)
                return handleVPTokenRequest(call, cex)
            }
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle Wallet requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleWalletRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Wallet $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(subId)
        val cex = FlowContext(ctx)

        // Handle CredentialOffer by Uri
        //
        if (path == "/wallet/$subId" && queryParams["credential_offer_uri"] != null) {
            return handleCredentialOffer(call, cex)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle Issuer Requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleIssuerRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Issuer $reqUri" }
        urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val ctx = requireLoginContext(subId)

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            return handleIssuerMetadataRequest(call, ctx)
        }

        // Handle Credential Request
        //
        if (path == "/issuer/$subId/credential") {
            val cex = requireCredentialExchange(subId)
            return handleCredentialRequest(call, cex)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle Authorization Requests -----------------------------------------------------------------------------------

    private suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {

        val payload = Json.encodeToString(AuthService.getAuthMetadata(ctx))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    /**
     * The Holder Wallet requests access for the required credentials from the Issuer's Authorisation Server.
     */
    private suspend fun handleAuthorizationRequest(call: RoutingCall, cex: FlowContext) {

        val queryParams = call.parameters.toMap()
        val authReq = AuthorizationRequest.fromHttpParameters(queryParams)
        log.info { "Authorization Request: ${Json.encodeToString(authReq)}" }
        queryParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val redirectUrl = AuthService.handleAuthorizationRequest(cex, authReq)
        call.respondRedirect(redirectUrl)
    }

    private suspend fun handleIDTokenRequest(call: RoutingCall, cex: FlowContext) {

        AuthService.handleIDTokenRequest(cex, call.parameters.toMap())

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleVPTokenRequest(call: RoutingCall, cex: FlowContext) {

        AuthService.handleVPTokenRequest(cex, call.parameters.toMap())

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleAuthDirectPost(call: RoutingCall, cex: FlowContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Authorization DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val redirectUrl = AuthService.handleIDTokenResponse(cex, postParams)
            return call.respondRedirect(redirectUrl)
        }

        if (postParams["vp_token"] != null) {
            val redirectUrl = AuthService.handleVPTokenResponse(cex, postParams)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    /**
     * Client requests key details
     */
    private suspend fun handleAuthJwksRequest(call: RoutingCall, ctx: LoginContext) {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val keys = mapOf("keys" to listOf(keyJwk))
        val payload = Json.encodeToString(keys)

        log.info { "Jwks $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    /**
     * Client requests an Access Token
     */
    private suspend fun handleAuthTokenRequest(call: RoutingCall, subId: String) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = when (tokenRequest) {
            is TokenRequest.AuthorizationCode -> {
                val cex = requireCredentialExchange(subId)
                AuthService.handleTokenRequestAuthCode(cex, tokenRequest)
            }

            is TokenRequest.PreAuthorizedCode -> {
                val cex = FlowContext(requireLoginContext(subId))
                AuthService.handleTokenRequestPreAuthorized(cex, tokenRequest)
            }
        }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokenResponse)
        )
    }

    // Handle Wallet Requests ------------------------------------------------------------------------------------------

    // Request and present Verifiable Credentials
    // https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows
    //
    // Issuer initiated flows start with the Credential Offering proposed by Issuer.
    // The Credential Offering is in redirect for same-device tests and in QR Code for cross-device tests.
    //
    private suspend fun handleCredentialOffer(call: RoutingCall, ctx: FlowContext) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        var credResponse = WalletService.getCredentialFromUri(ctx, oid4vcOfferUri)

        // In-Time CredentialResponses MUST have a 'format'
        var credJwt: SignedJWT? = null
        if (credResponse.format != null) {
            credJwt = credResponse.toSignedJWT()
        }

        // Deferred CredentialResponses have an 'acceptance_token'
        else if (credResponse.acceptanceToken != null) {
            // The credential will be available with a delay of 5 seconds from the first Credential Request.
            Thread.sleep(5500)
            val acceptanceToken = credResponse.acceptanceToken as String
            credResponse = WalletService.getDeferredCredential(ctx, acceptanceToken)
            credJwt = credResponse.toSignedJWT()
        }

        if (credJwt == null)
            throw IllegalStateException("No Credential JWT")

        // Verify that we can unmarshall the credential
        Json.decodeFromString<JwtCredential>("${credJwt.payload}")

        val walletId = ctx.walletInfo.id
        val format = credResponse.format as CredentialFormat
        widWalletSvc.addCredential(walletId, format, credJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }

    // Handle Issuer Requests ------------------------------------------------------------------------------------------

    private suspend fun handleIssuerMetadataRequest(call: RoutingCall, ctx: LoginContext) {

        val issuerMetadata = IssuerService.getIssuerMetadata(ctx)
        val payload = Json.encodeToString(issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    private suspend fun handleCredentialRequest(call: RoutingCall, cex: FlowContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequest>()
        val credentialResponse = IssuerService.getCredentialFromRequest(cex, accessToken, credReq)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    // Session Data ----------------------------------------------------------------------------------------------------

    private fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    private fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

    private fun getLoginContextFromSession(call: RoutingCall): LoginContext? {
        val dat = getCookieDataFromSession(call)
        val ctx = dat?.let { findLoginContext(it.wid, it.did ?: "") }
        return ctx
    }

    // LoginContext ----------------------------------------------------------------------------------------------------

    private suspend fun requireLoginContext(subId: String): LoginContext {

        // We expect the user to have logged in previously and have a valid Did
        //
        var ctx = findLoginContext(subId)

        // Fallback
        if (ctx == null) {
            val cfg = ConfigProvider.requireWalletConfig()
            if (cfg.userEmail.isNotBlank() && cfg.userPassword.isNotBlank()) {
                val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail, cfg.userPassword)
                ctx = widWalletSvc.loginWithWallet(loginParams)
                val subjectId = LoginContext.getSubjectId(ctx.walletInfo.id, "")
                sessions[subjectId] = ctx
            }
        }

        ctx ?: throw IllegalStateException("Login required")

        if (ctx.maybeDidInfo == null) {
            ctx.didInfo = widWalletSvc.findDidByPrefix(ctx, "did:key")
                ?: throw IllegalStateException("Cannot find required did in wallet")
        }

        return ctx
    }

    private fun findLoginContext(subjectId: String): LoginContext? {
        return sessions[subjectId]
    }

    fun findLoginContext(walletId: String, did: String): LoginContext? {
        val subjectId = LoginContext.Companion.getSubjectId(walletId, did)
        return findLoginContext(subjectId)
    }
}
