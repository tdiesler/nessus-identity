package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.getVersionInfo
import io.nessus.identity.console.SessionsStore.findOrCreateLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletAuthService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement

class VerifierHandler(val verifier: User) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()
    val verifierSvc = VerifierService.createKeycloak()
    val walletSvc = WalletService.createKeycloak()
    val walletAuthSvc = WalletAuthService(walletSvc)

    fun verifierModel(): MutableMap<String, Any> {
        val versionInfo = getVersionInfo()
        return mutableMapOf(
            "versionInfo" to versionInfo,
        )
    }

    suspend fun handleVerifierHome(call: RoutingCall) {
        val model = verifierModel()
        call.respond(
            FreeMarkerContent("verifier_home.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    suspend fun handlePresentationRequestGet(call: RoutingCall) {
        val model = verifierModel()
        model["subjects"] = issuerSvc.getRealmUsers().map { SubjectOption.fromUserRepresentation(it) }.toList()
        model["vctValues"] = issuerSvc.getIssuerMetadata().credentialConfigurationsSupported.keys
        model["claimsJson"] = jsonPretty.encodeToString(Json.decodeFromString<JsonArray>("""
          [
            { "path": ["email"], "values": ["alice@email.com"]}
          ]"""))
        call.respond(
            FreeMarkerContent("verifier_presentation_request.ftl", model)
        )
    }

    suspend fun handlePresentationRequestPost(call: RoutingCall) {
        val model = verifierModel()
        val params = call.receiveParameters()
        val subjectId = params["subjectId"] ?: error("No subjectId")
        val ctype = params["ctype"] ?: error("No ctype")
        val claims = params["claims"] ?: error("No claims")
        val metadata = issuerSvc.getIssuerMetadata()
        val credConfig = metadata.credentialConfigurationsSupported[ctype]
        val authContext = verifierSvc.authContextForPresentation(
            ctx = findOrCreateLoginContext(call, verifier),
            clientId = "oid4vcp",
            redirectUri = "urn:ietf:wg:oauth:2.0:oob",
            dcql = DCQLQuery.fromJson("""
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
                }"""))
        log.info { authContext.authRequest.toHttpParameters() }

        val holderCtx = when(subjectId) {
            Alice.email -> LoginContext.login(Alice).withWalletInfo()
            else -> error("Other users than Alice not (yet) supported")
        }

        val authRes = walletAuthSvc.authenticate(holderCtx,authContext.authRequest)
        val vpTokenJwt = SignedJWT.parse(authRes.vpToken)
        model["vpTokenHeader"] = jsonPretty.encodeToString(Json.decodeFromString<JsonElement>("${vpTokenJwt.header}"))
        model["vpTokenClaims"] = jsonPretty.encodeToString(Json.decodeFromString<JsonElement>("${vpTokenJwt.jwtClaimsSet}"))
        model["submissionJson"] = jsonPretty.encodeToString(authRes.presentationSubmission.toJSON())

        call.respond(
            FreeMarkerContent("verifier_presentation_details.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

}
