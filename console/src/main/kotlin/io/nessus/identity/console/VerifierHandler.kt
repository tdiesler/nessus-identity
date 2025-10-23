package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletAuthService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*

class VerifierHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()
    val verifierSvc = VerifierService.createKeycloak()
    val walletSvc = WalletService.createKeycloak()
    val walletAuthSvc = WalletAuthService(walletSvc)

    fun verifierModel(call: RoutingCall): BaseModel {
        val model = BaseModel()
            .withRoleAuth(call, UserRole.Holder)
            .withRoleAuth(call, UserRole.Verifier)
        return model
    }

    suspend fun verifierHomePage(call: RoutingCall) {
        val model = verifierModel(call)
        call.respond(
            FreeMarkerContent("verifier_home.ftl", model)
        )
    }

    suspend fun verifierLoginPage(call: RoutingCall) {
        val model = verifierModel(call)
        call.respond(
            FreeMarkerContent("verifier_login.ftl", model)
        )
    }

    suspend fun handleVerifierLogin(call: RoutingCall) {
        val params = call.receiveParameters()
        val email = params["email"] ?: error("No email")
        val password = params["password"] ?: error("No password")
        val loginParams = LoginParams(LoginType.EMAIL, email, password)
        SessionsStore.newLoginContext(call, UserRole.Verifier, loginParams)
        call.respondRedirect("/verifier")
    }

    suspend fun handleVerifierLogout(call: RoutingCall) {
        SessionsStore.logout(call, UserRole.Verifier)
        call.respondRedirect("/verifier")
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

    suspend fun handlePresentationRequest(call: RoutingCall) {

        requireLoginContext(call, UserRole.Verifier)
        val holderContext = requireLoginContext(call, UserRole.Holder)

        val model = verifierModel(call)
        val params = call.receiveParameters()
        val subjectId = params["subjectId"] ?: error("No subjectId")
        val ctype = params["ctype"] ?: error("No ctype")
        val claims = params["claims"] ?: error("No claims")
        val metadata = issuerSvc.getIssuerMetadata()
        val credConfig = metadata.credentialConfigurationsSupported[ctype]

        val authContext = verifierSvc.authContextForPresentation(
            clientId = "oid4vcp",
            redirectUri = "urn:ietf:wg:oauth:2.0:oob",
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
        ).withLoginContext(holderContext)

        log.info { authContext.authRequest.toHttpParameters() }

        val authRes = walletAuthSvc.authenticate(authContext)
        val vpTokenJwt = SignedJWT.parse(authRes.vpToken)
        val headerObj = Json.decodeFromString<JsonObject>("${vpTokenJwt.header}")
        val claimsObj = Json.decodeFromString<JsonObject>("${vpTokenJwt.jwtClaimsSet}")

        model["vpTokenHeader"] = jsonPretty.encodeToString(headerObj)
        model["vpTokenClaims"] = jsonPretty.encodeToString(claimsObj)
        model["submissionJson"] = jsonPretty.encodeToString(authRes.presentationSubmission.toJSON())

        val vpObj = claimsObj.getValue("vp").jsonObject
        val credsArr = vpObj.getValue("verifiableCredential").jsonArray
        val verifiableCredentials = credsArr.map {
            VCDataJwt.fromEncoded(it.jsonPrimitive.content).toJson()
        }
        model["verifiableCredentials"] = jsonPretty.encodeToString(verifiableCredentials)

        call.respond(
            FreeMarkerContent("verifier_presentation_details.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}
