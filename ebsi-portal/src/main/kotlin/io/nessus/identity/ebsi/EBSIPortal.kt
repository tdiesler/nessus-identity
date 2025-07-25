package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import freemarker.cache.ClassTemplateLoader
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
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
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.config.redacted
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.AuthService
import io.nessus.identity.service.CookieData
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDCContext
import io.nessus.identity.service.OIDCContextRegistry
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.service.http
import io.nessus.identity.service.toSignedJWT
import io.nessus.identity.service.urlQueryToMap
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
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
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

        log.info { "Auth $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        if (path.endsWith(".well-known/openid-configuration")) {
            val ctx = requireLoginContext(svcId)
            return handleAuthorizationMetadataRequest(call, ctx)
        }

        // AuthorizationRequest endpoint
        // 
        if (path == "/auth/$svcId/authorize") {
            val ctx = OIDCContext(requireLoginContext(svcId))
            return handleAuthorizationRequest(call, ctx)
        }

        // direct_post
        //
        if (path == "/auth/$svcId/direct_post") {
            val ctx = OIDCContextRegistry.assert(svcId)
            return handleAuthDirectPost(call, ctx)
        }

        // JWKS endpoint
        //
        if (path == "/auth/$svcId/jwks") {
            val ctx = requireLoginContext(svcId)
            return handleAuthJwksRequest(call, ctx)
        }

        // Token endpoint
        //
        if (path == "/auth/$svcId/token") {
            return handleAuthTokenRequest(call, svcId)
        }

        // Callback as part of the AuthorizationRequest
        //
        if (path == "/auth/$svcId") {
            val ctx = OIDCContextRegistry.assert(svcId)
            val responseType = queryParams["response_type"]
            return when (responseType) {
                "id_token" -> handleIDTokenRequest(call, ctx)
                "vp_token" -> handleVPTokenRequest(call, ctx)
                else -> throw IllegalArgumentException("Unknown response type: $responseType")
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

        // Handle CredentialOffer by Uri
        //
        if (path == "/wallet/$svcId" && queryParams["credential_offer_uri"] != null) {
            val ctx = OIDCContext(requireLoginContext(svcId))
            return handleCredentialOffer(call, ctx)
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
            val ctx = OIDCContextRegistry.assert(svcId)
            return handleCredentialRequest(call, ctx)
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

        AuthService.validateAuthorizationRequest(ctx, authReq)
        val isVPTokenRequest = authReq.scope.any { it.contains("vp_token") }
        val redirectUrl = if (isVPTokenRequest) {
            val vpTokenReqJwt = AuthService.buildVPTokenRequest(ctx, authReq)
            AuthService.buildVPTokenRedirectUrl(ctx, vpTokenReqJwt)
        } else {
            val idTokenReqJwt = AuthService.buildIDTokenRequest(ctx, authReq)
            AuthService.buildIDTokenRedirectUrl(ctx, idTokenReqJwt)
        }
        call.respondRedirect(redirectUrl)
    }

    private suspend fun handleIDTokenRequest(call: RoutingCall, ctx: OIDCContext) {

        val reqParams = urlQueryToMap(call.request.uri).toMutableMap()
        val redirectUri = reqParams["redirect_uri"] as String

        // Replace IDToken request params with the response from request_uri
        reqParams["request_uri"]?.also { requestUri ->
            log.info { "IDToken params from: $requestUri" }
            val res = http.get(requestUri)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val uriRes = res.bodyAsText()
            log.info { "UriResponse: $uriRes" }
            val resJwt = SignedJWT.parse(uriRes)
            log.info { "UriResponse Header: ${resJwt.header}" }
            log.info { "UriResponse Claims: ${resJwt.jwtClaimsSet}" }
            for ((k, v) in resJwt.jwtClaimsSet.claims) {
                reqParams[k] = "$v"
            }
        }

        val idTokenJwt = WalletService.createIDToken(ctx, reqParams)
        WalletService.sendIDToken(ctx, redirectUri, idTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleVPTokenRequest(call: RoutingCall, ctx: OIDCContext) {

        val reqParams = urlQueryToMap(call.request.uri)

        // Final Qualification Credential use case ...
        //
        //  - EBSI offers the CTWalletQualificationCredential
        //  - Holder sends an AuthorizationRequest, EBSI responds with an 302 Redirect (WalletService.sendAuthorizationRequest)
        //  - Cloudflare may deny that redirect URL because of a very large 'request' query parameter
        //  - The content of that request parameter is a serialized AuthorizationRequest object
        //  - We rewrite the redirect URL using a request_uri parameter, which resolves to that AuthorizationRequest
        //  - Here, we restore that AuthorizationRequest and use it's PresentationDefinition to build the VPToken

        var authReq = ctx.assertAttachment(AUTH_REQUEST_ATTACHMENT_KEY)

        val requestUri = reqParams["request_uri"]
        if (requestUri != null) {

            if (!requestUri.startsWith(authEndpointUri))
                throw IllegalStateException("Unexpected request_uri: $requestUri")

            val reqObjectId = urlQueryToMap(requestUri)["request_object"]
            if (reqObjectId == null)
                throw IllegalStateException("No request_object in: $requestUri")

            // [TODO] Select request_uri object by id
            authReq = ctx.assertAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY) as AuthorizationRequest
        }

        val vpTokenJwt = WalletService.createVPToken(ctx, authReq)
        WalletService.sendVPToken(ctx, vpTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    private suspend fun handleAuthDirectPost(call: RoutingCall, ctx: OIDCContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Auth DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val authCode = AuthService.validateIDToken(ctx, idTokenJwt)
            val redirectUrl = AuthService.buildAuthCodeRedirectUri(ctx, authCode)
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

        val tokenReq = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = when (tokenReq) {
            is TokenRequest.AuthorizationCode -> {
                val ctx = OIDCContextRegistry.assert(svcId)
                AuthService.handleTokenRequestAuthCode(ctx, tokenReq)
            }

            is TokenRequest.PreAuthorizedCode -> {
                val ctx = OIDCContext(requireLoginContext(svcId))
                AuthService.handleTokenRequestPreAuthorized(ctx, tokenReq)
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
        val credOffer = WalletService.getCredentialOfferFromUri(ctx, oid4vcOfferUri)
        var credRes = WalletService.getCredentialFromOffer(ctx, credOffer)

        // In-Time CredentialResponses MUST have a 'format'
        var credJwt: SignedJWT? = null
        if (credRes.format != null) {
            credJwt = credRes.toSignedJWT()
        }

        // Deferred CredentialResponses have an 'acceptance_token'
        else if (credRes.acceptanceToken != null) {
            // The credential will be available with a delay of 5 seconds from the first Credential Request.
            Thread.sleep(5500)
            val acceptanceToken = credRes.acceptanceToken as String
            credRes = WalletService.getDeferredCredential(ctx, acceptanceToken)
            credJwt = credRes.toSignedJWT()
        }

        if (credJwt == null)
            throw IllegalStateException("No Credential JWT")

        WalletService.addCredential(ctx, credRes)

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
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = IssuerService.credentialFromRequest(ctx, credReq, accessTokenJwt)

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
