package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import freemarker.cache.ClassTemplateLoader
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.freemarker.FreeMarker
import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.receive
import io.ktor.server.request.receiveParameters
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.util.toMap
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.redacted
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AuthService
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.OIDCContextRegistry
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.getVersionInfo
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

fun main() {
    val server = EBSIPortal().createServer()
    server.start(wait = true)
}

class EBSIPortal {

    val log = KotlinLogging.logger {}

    // Registry that allows us to restore a LoginContext from subjectId
    private val sessions = mutableMapOf<String, LoginContext>()
    private val versionInfo = getVersionInfo()

    constructor() {
        log.info { "Starting the Nessus EBSI Conformance Portal ..." }
        val serverConfig = ConfigProvider.requireServerConfig()
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val databaseConfig = ConfigProvider.requireDatabaseConfig()
        log.info { "ServerConfig: ${Json.encodeToString(serverConfig)}" }
        log.info { "ServiceConfig: ${Json.encodeToString(serviceConfig)}" }
        log.info { "DatabaseConfig: ${Json.encodeToString(databaseConfig.redacted())}" }
        log.info { "VersionInfo: ${Json.encodeToString(versionInfo)}" }
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
                route("/auth/{svcId}/{...}") {
                    handle {
                        val svcId = call.parameters["svcId"] ?: throw IllegalArgumentException("No svcId")
                        handleAuthRequests(call, svcId)
                    }
                }
                route("/wallet/{svcId}/{...}") {
                    handle {
                        val svcId = call.parameters["svcId"] ?: throw IllegalArgumentException("No svcId")
                        handleWalletRequests(call, svcId)
                    }
                }
                route("/issuer/{svcId}/{...}") {
                    handle {
                        val svcId = call.parameters["svcId"] ?: throw IllegalArgumentException("No svcId")
                        handleIssuerRequests(call, svcId)
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
            "versionInfo" to versionInfo,
        )
        if (ctx?.hasWalletInfo == true) {
            model["subjectId"] = ctx.targetId
            model["walletUri"] = "${ConfigProvider.walletEndpointUri}/${ctx.targetId}"
            model["issuerUri"] = "${ConfigProvider.issuerEndpointUri}/${ctx.targetId}"
            model["authUri"] = "${ConfigProvider.authEndpointUri}/${ctx.targetId}"
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
                ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, it)
            }
            val wid = ctx.walletId
            val did = ctx.maybeDidInfo?.did
            setCookieDataInSession(call, CookieData(wid, did))
            val targetId = LoginContext.getTargetId(wid, did ?: "")
            sessions[targetId] = ctx
        }
    }

    // Handle Authorization Requests -----------------------------------------------------------------------------------
    //
    suspend fun handleAuthRequests(call: RoutingCall, svcId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Authorization $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(svcId)

        if (path.endsWith(".well-known/openid-configuration")) {
            return handleAuthorizationMetadataRequest(call, ctx)
        }

        // authorize
        // 
        if (path == "/auth/$svcId/authorize") {
            val cex = OIDCContext(ctx)
            return handleAuthorizationRequest(call, cex)
        }

        // direct_post
        //
        if (path == "/auth/$svcId/direct_post") {
            val cex = OIDCContextRegistry.assert(svcId)
            return handleAuthDirectPost(call, cex)
        }

        // jwks
        //
        if (path == "/auth/$svcId/jwks") {
            return handleAuthJwksRequest(call, ctx)
        }

        // token
        //
        if (path == "/auth/$svcId/token") {
            return handleAuthTokenRequest(call, svcId)
        }

        // Callback as part of the Authorization Request
        //
        if (path == "/auth/$svcId") {
            val responseType = queryParams["response_type"]
            if (responseType == "id_token") {
                val cex = OIDCContextRegistry.assert(svcId)
                return handleIDTokenRequest(call, cex)
            }
            if (responseType == "vp_token") {
                val cex = OIDCContextRegistry.assert(svcId)
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
    suspend fun handleWalletRequests(call: RoutingCall, svcId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Wallet $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(svcId)
        val cex = OIDCContext(ctx)

        // Handle CredentialOffer by Uri
        //
        if (path == "/wallet/$svcId" && queryParams["credential_offer_uri"] != null) {
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
    suspend fun handleIssuerRequests(call: RoutingCall, svcId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Issuer $reqUri" }
        urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val ctx = requireLoginContext(svcId)

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            return handleIssuerMetadataRequest(call, ctx)
        }

        // Handle Credential Request
        //
        if (path == "/issuer/$svcId/credential") {
            val cex = OIDCContextRegistry.assert(svcId)
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
    private suspend fun handleAuthorizationRequest(call: RoutingCall, ctx: OIDCContext) {

        val queryParams = call.parameters.toMap()
        val authReq = AuthorizationRequest.fromHttpParameters(queryParams)
        log.info { "Authorization Request: ${Json.encodeToString(authReq)}" }
        queryParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val redirectUrl = AuthService.handleAuthorizationRequest(ctx, authReq)
        call.respondRedirect(redirectUrl)
    }

    private suspend fun handleIDTokenRequest(call: RoutingCall, ctx: OIDCContext) {

        AuthService.handleIDTokenRequest(ctx, call.parameters.toMap())

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleVPTokenRequest(call: RoutingCall, ctx: OIDCContext) {

        AuthService.handleVPTokenRequest(ctx, call.parameters.toMap())

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleAuthDirectPost(call: RoutingCall, ctx: OIDCContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Authorization DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val redirectUrl = AuthService.handleIDTokenResponse(ctx, postParams)
            return call.respondRedirect(redirectUrl)
        }

        if (postParams["vp_token"] != null) {
            val redirectUrl = AuthService.handleVPTokenResponse(ctx, postParams)
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
    private suspend fun handleAuthTokenRequest(call: RoutingCall, svcId: String) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = when (tokenRequest) {
            is TokenRequest.AuthorizationCode -> {
                val cex = OIDCContextRegistry.assert(svcId)
                AuthService.handleTokenRequestAuthCode(cex, tokenRequest)
            }

            is TokenRequest.PreAuthorizedCode -> {
                val cex = OIDCContext(requireLoginContext(svcId))
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
    private suspend fun handleCredentialOffer(call: RoutingCall, ctx: OIDCContext) {

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

        val walletId = ctx.walletId
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

    private suspend fun handleCredentialRequest(call: RoutingCall, ctx: OIDCContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequest>()
        val credentialResponse = IssuerService.getCredentialFromRequest(ctx, accessToken, credReq)

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

    private suspend fun requireLoginContext(svcId: String): LoginContext {

        // We expect the user to have logged in previously and have a valid Did
        //
        var ctx = findLoginContext(svcId)

        // Fallback
        if (ctx == null) {
            val cfg = ConfigProvider.requireWalletConfig()
            if (cfg.userEmail.isNotBlank() && cfg.userPassword.isNotBlank()) {
                val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail, cfg.userPassword)
                ctx = widWalletSvc.loginWithWallet(loginParams)
                val subjectId = LoginContext.getTargetId(ctx.walletId, "")
                sessions[subjectId] = ctx
            }
        }

        ctx ?: throw IllegalStateException("Login required")

        if (ctx.maybeDidInfo == null) {
            val didInfo = widWalletSvc.findDidByPrefix(ctx, "did:key")
                ?: throw IllegalStateException("Cannot find required did in wallet")
            ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, didInfo)
        }

        return ctx
    }

    private fun findLoginContext(subjectId: String): LoginContext? {
        return sessions[subjectId]
    }

    fun findLoginContext(walletId: String, did: String): LoginContext? {
        val subjectId = LoginContext.Companion.getTargetId(walletId, did)
        return findLoginContext(subjectId)
    }
}
