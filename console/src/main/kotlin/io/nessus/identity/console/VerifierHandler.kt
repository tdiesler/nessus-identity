package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireVerifierConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_RESPONSE_ATTACHMENT_KEY
import io.nessus.identity.service.VerifierService
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*

class VerifierHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()
    val verifierSvc = VerifierService.createKeycloak()

    fun verifierModel(call: RoutingCall): BaseModel {
        val model = BaseModel()
            .withLoginContext(call, UserRole.Holder)
            .withLoginContext(call, UserRole.Verifier)
        return model
    }

    suspend fun showHome(call: RoutingCall) {
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

    suspend fun handleLogout(call: RoutingCall) {
        SessionsStore.logout(call, UserRole.Verifier)
        call.respondRedirect("/verifier")
    }

    suspend fun handleVerifierCallback(call: RoutingCall, ctx: LoginContext) {

        val authRes = ctx.getAttachment(AUTH_RESPONSE_ATTACHMENT_KEY) as TokenResponse
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

    suspend fun handleVerifierDirectPost(call: RoutingCall) {

        // A direct post would likely not have a session cookie from which we can derive the Verifier session.
        // Instead, we expect a single Verifier LoginContext that already exists.
        val verifierContexts = SessionsStore.loginContexts.values
            .filter { it.userRole == UserRole.Verifier }
        if (verifierContexts.isEmpty())
            error("No Verifier LoginContext")
        if (verifierContexts.size > 1)
            error("Multiple Verifier LoginContexts")

        val authResJson = call.receiveText()
        val authRes = TokenResponse.fromJson(authResJson)
        verifierContexts[0].putAttachment(AUTH_RESPONSE_ATTACHMENT_KEY, authRes)

        // If the Response URI has successfully processed the Authorization Response or Authorization Error Response,
        // it MUST respond with an HTTP status code of 200 with Content-Type of application/json and a JSON object in the response body.

        val responseUri = requireVerifierConfig().responseUri
        call.respond(mapOf("redirect_uri" to responseUri))
    }

    suspend fun handlePresentationRequest(call: RoutingCall) {

        requireLoginContext(call, UserRole.Verifier)

        val params = call.receiveParameters()
        val ctype = params["ctype"] ?: error("No ctype")
        val claims = params["claims"] ?: error("No claims")
        val metadata = issuerSvc.getIssuerMetadata()
        val credConfig = metadata.credentialConfigurationsSupported[ctype]

        val responseUri = requireVerifierConfig().responseUri
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

        val walletAuthUrl = requireWalletConfig().authUri
        val redirectUrl = authReq.getAuthorizationRequestUrl(walletAuthUrl)

        log.info { redirectUrl }
        call.respondRedirect(redirectUrl)
    }

    suspend fun showPresentationRequestPage(call: RoutingCall) {
        val model = verifierModel(call)
        val holderContext = model["holderAuth"] as LoginContext
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

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}
