package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginContext.Companion.AUTH_RESPONSE_ATTACHMENT_KEY
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.console.SessionsStore.createLoginContext
import io.nessus.identity.console.SessionsStore.logout
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.LoginParams
import io.nessus.identity.types.LoginType
import io.nessus.identity.types.PresentationDefinitionBuilder
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.publicKeyJwk
import io.nessus.identity.utils.signWithKey
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

class VerifierHandler(val walletSvc: WalletService, val issuerSvc: IssuerService, val verifierSvc: VerifierService) {

    val log = KotlinLogging.logger {}
    val jsonPretty = Json { prettyPrint = true }

    val endpointUri = verifierSvc.endpointUri

    fun verifierModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val model = ctx?.let { BaseModel().withLoginContext(ctx) } ?: BaseModel().withLoginContext(call, UserRole.Verifier)
        val verifier = model.loginContexts[UserRole.Verifier] as LoginContext
        if (verifier.hasAuthToken) {
            model["verifierName"] = verifier.walletInfo.name
            model["verifierDid"] = verifier.didInfo.did
            model["verifierUri"] = "${verifierSvc.endpointUri}/${verifier.targetId}"
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
        createLoginContext(call, UserRole.Verifier, loginParams)
        call.respondRedirect("/verifier")
    }

    suspend fun handleLogout(call: RoutingCall, ctx: LoginContext) {
        logout(call, ctx.targetId)
        call.respondRedirect("/verifier")
    }

    suspend fun handleAuthCallback(call: RoutingCall, ctx: LoginContext) {

        val authResJson = call.receiveText()
        val authRes = TokenResponse.fromJson(authResJson)
        ctx.putAttachment(AUTH_RESPONSE_ATTACHMENT_KEY, authRes)

        // If the Response URI has successfully processed the Authorization Response or Authorization Error Response,
        // it MUST respond with an HTTP status code of 200 with Content-Type of application/json and a JSON object in the response body.

        val responseUri = "${verifierSvc.endpointUri}/presentation-response"
        call.respond(mapOf("redirect_uri" to responseUri))
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
        // [TODO] migrate ctype to configId
        val ctype = params["ctype"] ?: error("No ctype")
        val claims = params["claims"] ?: error("No claims")

        val issuerMetadata = issuerSvc.getIssuerMetadata()
        val format = issuerMetadata.getCredentialFormat(ctype) ?: error("No format for: $ctype")

        val responseUri = "${verifierSvc.endpointUri}/auth/callback/${ctx.targetId}"
        val authReq = verifierSvc.buildAuthorizationRequestForPresentation(
            clientId = "oid4vcp",
            responseUri = responseUri,
            dcql = DCQLQuery.fromJson(
                """
                {
                  "credentials": [
                    {
                      "id": "queryId",
                      "format": "${format.value}",
                      "meta": {
                        "vct_values": [ "$ctype" ]
                      },
                      "claims": $claims
                    }
                  ]
                }"""
            )
        )

        val walletTargetUri = "${walletSvc.endpointUri}/$targetId"
        val redirectUrl = authReq.toRequestUrl("$walletTargetUri/authorize")
        log.info { "Verifier sends AuthorizationRequest: $redirectUrl" }
        authReq.toRequestParameters().entries.forEach { (k, v) -> log.info { "  $k=$v" } }

        call.respondRedirect(redirectUrl)
    }

    suspend fun showAuthConfig(call: RoutingCall, ctx: LoginContext) {
        val verifierTargetUri = "${verifierSvc.endpointUri}/${ctx.targetId}"
        val authMetadata = verifierSvc.authorizationSvc.getAuthorizationMetadata(ctx)
        val prettyJson = jsonPretty.encodeToString(authMetadata)
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
        val issuerMetadata = issuerSvc.getIssuerMetadata() as IssuerMetadataV0
        val model = verifierModel(call)
        model["targetId"] = holderContext.targetId
        model["subInfo"] = widWalletService.authUserInfo(holderContext.authToken) ?: error("No WaltIdUser")
        model["vctValues"] = issuerMetadata.credentialConfigurationsSupported.keys
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

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val presentationDefinition = authReq.presentationDefinition ?: run {

            require(authReq.scope?.contains("vp_token") ?: false) { "No PresentationDefinition" }

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
                .claim("scope", authReq.scope)
                .claim("nonce", "${Uuid.random()}")
                .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson)).build()

        val vpTokenReqJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPTokenRequest Header: ${vpTokenReqJwt.header}" }
        log.info { "VPTokenRequest Claims: ${vpTokenReqJwt.jwtClaimsSet}" }

        return vpTokenReqJwt
    }
}
