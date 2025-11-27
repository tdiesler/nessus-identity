package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.crypto.utils.JsonUtils.toJsonElement
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext.Companion.AUTH_RESPONSE_ATTACHMENT_KEY
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletAuthorizationService.Companion.buildAuthorizationMetadata
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.PresentationDefinitionBuilder
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

class VerifierHandler : AuthHandler() {

    val issuerSvc = IssuerService.createKeycloak()
    val verifierSvc = VerifierService.create()

    override val endpointUri = verifierSvc.verifierEndpointUri

    fun verifierModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val model = ctx?.let { BaseModel().withLoginContext(ctx) } ?: BaseModel().withLoginContext(call, UserRole.Verifier)
        val verifier = model.loginContexts[UserRole.Verifier] as LoginContext
        if (verifier.hasAuthToken) {
            model["verifierName"] = verifier.walletInfo.name
            model["verifierDid"] = verifier.didInfo.did
            model["verifierUri"] = "${verifierSvc.verifierEndpointUri}/${verifier.targetId}"
        }
        return model
    }

    suspend fun showHome(call: RoutingCall, ctx: LoginContext?) {
        val model = verifierModel(call)
        call.respond(
            FreeMarkerContent("verifier_home.ftl", model)
        )
    }

    suspend fun showLoginPage(call: RoutingCall) {
        val model = verifierModel(call)
        call.respond(
            FreeMarkerContent("verifier_login.ftl", model)
        )
    }

    suspend fun handleLogin(call: RoutingCall) {
        val params = call.receiveParameters()
        val email = params["email"] ?: error("No email")
        val password = params["password"] ?: error("No password")
        val loginParams = LoginParams(LoginType.EMAIL, email, password)
        SessionsStore.createLoginContext(call, UserRole.Verifier, loginParams)
        call.respondRedirect("/verifier")
    }

    suspend fun handleLogout(call: RoutingCall, ctx: LoginContext) {
        SessionsStore.logout(call, ctx.targetId)
        call.respondRedirect("/verifier")
    }

    suspend fun handleAuthCallback(call: RoutingCall, ctx: LoginContext) {

        val authResJson = call.receiveText()
        val authRes = TokenResponse.fromJson(authResJson)
        ctx.putAttachment(AUTH_RESPONSE_ATTACHMENT_KEY, authRes)

        // If the Response URI has successfully processed the Authorization Response or Authorization Error Response,
        // it MUST respond with an HTTP status code of 200 with Content-Type of application/json and a JSON object in the response body.

        val responseUri = "${verifierSvc.verifierEndpointUri}/presentation-response"
        call.respond(mapOf("redirect_uri" to responseUri))
    }

    suspend fun handleAuthorization(call: RoutingCall, ctx: LoginContext) {

        log.info { "Verifier receives AuthorizationRequest: ${call.request.uri}" }
        val queryParams = urlQueryToMap(call.request.uri)
        queryParams.entries.forEach { (k, v) -> log.info { "  $k=$v" } }

        val scopes = call.parameters["scope"]?.split(" ") ?: listOf()

        when {
            scopes.any { it.contains("id_token") } -> {
                val authContext = AuthorizationContext.create(ctx)
                val authRequest = AuthorizationRequestDraft11.fromHttpParameters(call.request.queryParameters.toMap())
                authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)
                val idTokenReqJwt = buildIDTokenRequest(ctx, authRequest)
                val authRequestRedirectUri = authRequest.redirectUri as String
                val redirectUrl = buildIDTokenRedirectUrl(authRequestRedirectUri, idTokenReqJwt)
                return call.respondRedirect(redirectUrl)
            }
            scopes.any { it.contains("vp_token") } -> {
                val authContext = AuthorizationContext.create(ctx)
                val authRequest = AuthorizationRequestDraft11.fromHttpParameters(call.request.queryParameters.toMap())
                authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)
                val vpTokenReqJwt = buildVPTokenRequest(ctx, authRequest)
                val redirectUrl = buildVPTokenRedirectUrl(ctx, authRequest, vpTokenReqJwt)
                return call.respondRedirect(redirectUrl)
            }
            else -> error{ "Unknown authorization request" }
        }
    }

    suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {
        val walletTargetUri = "${verifierSvc.verifierEndpointUri}/${ctx.targetId}"
        val payload = Json.encodeToString(buildAuthorizationMetadata(walletTargetUri))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleDirectPost(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Verifier DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val authCode = validateIDToken(ctx, idTokenJwt)
            val redirectUrl = buildAuthCodeRedirectUri(ctx, authCode)
            return call.respondRedirect(redirectUrl)
        }

        if (postParams["vp_token"] != null) {
            val redirectUrl = handleVPTokenResponse(ctx, postParams)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    /**
     * Verifiable Presentation Flow
     *
     * 1. Verifier handles VP Request (i.e. POST to /verifier/presentation-request)
     *      - constructs an AuthorizationRequest with a DCQLQuery and response_type=vp_token
     *      - respond with a redirect to the Wallet's authorization endpoint
     * 2. Wallet processes the AuthorizationRequest (i.e. GET to /wallet/{targetId}/authorize)
     *      - stores AuthorizationRequest in its context
     *      - redirects to /wallet/auth/flow/vp-token-consent?state=ask
     * 3. Wallet show VP Token Consent page (i.e. GET to /wallet/{targetId}/flow/vp-token-consent)
     *      - user can inspect the VP Request and respond with accept or reject
     * 4. Wallet receives the outcome of the VP consent page (i.e. POST to /wallet/auth/flow/vp-token-consent)
     *      - on accept and with response_mode=direct_post the Wallet send a POST to the given response_uri
     * 5. Verifier receives the Wallet's response (i.e. POST to /verifier/auth/callback/{targetId})
     *      - verifier stores the TP Token in its context
     *      - verifier responds with a simple json payload that contains a redirect_uri=/verifier/presentation-result
     * 6. Wallet get the result of the direct post
     *      - redirects to the given Verifier's redirect uri
     */
    suspend fun handlePresentationRequest(call: RoutingCall, ctx: LoginContext) {

        val params = call.receiveParameters()
        val targetId = params["targetId"] ?: error("No targetId")
        val ctype = params["ctype"] ?: error("No ctype")
        val claims = params["claims"] ?: error("No claims")

        val metadata = issuerSvc.getIssuerMetadata()
        val credConfig = metadata.credentialConfigurationsSupported[ctype]

        val responseUri = "${verifierSvc.verifierEndpointUri}/auth/callback/${ctx.targetId}"
        val authReq = verifierSvc.buildAuthorizationRequestForPresentation(
            clientId = "oid4vcp",
            responseUri = responseUri,
            dcql = DCQLQuery.fromJson(
                """
                {
                  "credentials": [
                    {
                      "id": "queryId",
                      "format": "${credConfig!!.format}",
                      "meta": {
                        "vct_values": [ "$ctype" ]
                      },
                      "claims": $claims
                    }
                  ]
                }"""
            )
        )

        val walletTargetUri = "${walletSvc.walletEndpointUri}/$targetId"
        val redirectUrl = authReq.getAuthorizationRequestUrl("$walletTargetUri/authorize")
        log.info { "Verifier sends AuthorizationRequest: $redirectUrl" }
        authReq.getParameters().entries.forEach { (k, v) -> log.info { "  $k=$v" } }

        call.respondRedirect(redirectUrl)
    }

    suspend fun showAuthConfig(call: RoutingCall, ctx: LoginContext) {
        val verifierTargetUri = "${verifierSvc.verifierEndpointUri}/${ctx.targetId}"
        val authConfig = buildAuthorizationMetadata(verifierTargetUri)
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val authConfigUrl = "$verifierTargetUri/.well-known/openid-configuration"
        val model = verifierModel(call).also {
            it["authConfigJson"] = prettyJson
            it["authConfigUrl"] = authConfigUrl
        }
        call.respond(
            FreeMarkerContent("verifier_auth_config.ftl", model)
        )
    }

    suspend fun showPresentationRequest(call: RoutingCall, holderContext: LoginContext) {
        val model = verifierModel(call)
        model["targetId"] = holderContext.targetId
        model["subInfo"] = widWalletService.authUserInfo(holderContext.authToken) ?: error("No UserInfo")
        model["vctValues"] = issuerSvc.getIssuerMetadata().credentialConfigurationsSupported.keys
        model["claimsJson"] = jsonPretty.encodeToString(
            Json.decodeFromString<JsonArray>(
                """
          [
            { "path": ["email"], "values": ["alice@email.com"]}
          ]"""
            )
        )
        call.respond(
            FreeMarkerContent("verifier_presentation_request.ftl", model)
        )
    }

    suspend fun showPresentationResponse(call: RoutingCall, ctx: LoginContext) {

        val authRes = ctx.assertAttachment(AUTH_RESPONSE_ATTACHMENT_KEY)
        val vpSubmission = authRes.presentationSubmission ?: error("No presentation_submission")

        val vpTokenJwt = SignedJWT.parse(authRes.vpToken)
        val headerObj = Json.decodeFromString<JsonObject>("${vpTokenJwt.header}")
        val claimsObj = Json.decodeFromString<JsonObject>("${vpTokenJwt.jwtClaimsSet}")

        val model = verifierModel(call)
        model["vpTokenHeader"] = jsonPretty.encodeToString(headerObj)
        model["vpTokenClaims"] = jsonPretty.encodeToString(claimsObj)
        model["submissionJson"] = jsonPretty.encodeToString(vpSubmission.toJSON())

        val vpObj = claimsObj.getValue("vp").jsonObject
        val credsArr = vpObj.getValue("verifiableCredential").jsonArray
        val verifiableCredentials = credsArr.map {
            W3CCredentialJwt.fromEncoded(it.jsonPrimitive.content).toJson()
        }
        model["verifiableCredentials"] = jsonPretty.encodeToString(verifiableCredentials)

        call.respond(
            FreeMarkerContent("verifier_presentation_details.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestDraft11): SignedJWT {

        val requesterDid = requireEbsiConfig().requesterDid
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val scopes = authReq.scope.joinToString(" ")

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val presentationDefinition = authReq.presentationDefinition ?: run {

            require(authReq.scope == setOf("openid", "ver_test:vp_token")) { "No PresentationDefinition" }

            // EBSI wants exactly three InputDescriptor(s)
            // Authorization endpoint's response doesn't contain a valid JWT payload in the VP Token request
            // Validation error. Path: 'presentation_definition.input_descriptors'. Reason: Array must contain exactly 3 element(s)
            PresentationDefinitionBuilder().withInputDescriptorForType("VerifiableAttestation")
                .withInputDescriptorForType("VerifiableAttestation").withInputDescriptorForType("VerifiableAttestation")
                .build()
        }

        val presentationDefinitionJson = Json.encodeToString(presentationDefinition)
        log.info { "PresentationDefinition: $presentationDefinitionJson" }

        val vpTokenClaims =
            JWTClaimsSet.Builder().issuer(requesterDid).audience(authReq.clientId)
                .issueTime(Date.from(iat)).expirationTime(Date.from(exp)).claim("response_type", "vp_token")
                .claim("response_mode", "direct_post")
                .claim("client_id", requesterDid)
                .claim("redirect_uri", "$targetEndpointUri/direct_post")
                .claim("scope", scopes)
                .claim("nonce", "${Uuid.random()}")
                .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson)).build()

        val vpTokenReqJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPTokenRequest Header: ${vpTokenReqJwt.header}" }
        log.info { "VPTokenRequest Claims: ${vpTokenReqJwt.jwtClaimsSet}" }

        return vpTokenReqJwt
    }

    private fun buildVPTokenRedirectUrl(ctx: LoginContext, authReq: AuthorizationRequestDraft11, vpTokenReqJwt: SignedJWT): String {

        val scopes = authReq.scope.joinToString(" ")
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

        // Is VPTokenRequest payload an AuthorizationRequest?
        // https://github.com/tdiesler/nessus-identity/issues/226
        val vpTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authReq.clientId) // Holder Did
            parameters.append("response_type", "vp_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", scopes)
            parameters.append("redirect_uri", "$targetEndpointUri/direct_post")
            // [TODO #227] May need to use request_uri for VPToken Request redirect url
            // https://github.com/tdiesler/nessus-identity/issues/227
            parameters.append("request", "${vpTokenReqJwt.serialize()}")
        }.buildString()

        log.info { "VPToken Redirect $vpTokenRedirectUrl" }
        urlQueryToMap(vpTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirectUrl
    }

    private fun handleVPTokenResponse(ctx: LoginContext, postParams: Map<String, List<String>>): String {

        val vpToken = postParams["vp_token"]?.firstOrNull() ?: error("No vp_token")

        val vpTokenJwt = SignedJWT.parse(vpToken)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        // Validate VPToken
        //
        val vpClaims = vpTokenJwt.jwtClaimsSet
        vpClaims.expirationTime?.also {
            if (it.before(Date())) {
                throw IllegalStateException("Token has expired on: $it")
            }
        }
        vpClaims.notBeforeTime?.also {
            if (Date().before(it)) {
                throw IllegalStateException("Token cannot be used before: $it")
            }
        }

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
        val urlBuilder = URLBuilder("${authReq.redirectUri}")

        val vcArray = vpClaims.getClaim("vp").toJsonElement().jsonObject["verifiableCredential"]?.jsonArray

        // Validate Credentials
        //
        var validationError: Throwable? = null
        log.info { "VPToken VerifiableCredentials" }
        vcArray?.map { it.jsonPrimitive.content }?.forEach { vcEncoded ->
            val jwt = SignedJWT.parse(vcEncoded)
            log.info { "VC Encoded: $vcEncoded" }
            log.info { "   Header: ${jwt.header}" }
            log.info { "   Claims: ${jwt.jwtClaimsSet}" }
            runCatching {
                val vpcJwt = W3CCredentialV11Jwt.fromEncoded(vcEncoded)
                verifierSvc.validateVerifiableCredential(vpcJwt)
            }.onFailure {
                validationError = it
                urlBuilder.apply {
                    parameters.append("error", "invalid_request")
                    parameters.append("error_description", "${validationError.message}")
                }
            }
        }

        if (validationError == null) {
            urlBuilder.parameters.append("code", "${Uuid.random()}")
        }
        if (authReq.state != null) {
            urlBuilder.parameters.append("state", "${authReq.state}")
        }

        val redirectUrl = urlBuilder.buildString()
        log.info { "VPToken Response $redirectUrl" }
        urlQueryToMap(redirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }
        return redirectUrl
    }
}
