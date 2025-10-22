package io.nessus.identity.console

import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletAuthService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.VCDataJwt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class VerifierHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val issuerSvc = IssuerService.createKeycloak()
    val verifierSvc = VerifierService.createKeycloak()
    val walletSvc = WalletService.createKeycloak()
    val walletAuthSvc = WalletAuthService(walletSvc)

    fun verifierModel(call: RoutingCall): BaseModel {
        return BaseModel(call)
    }

    suspend fun verifierHomePage(call: RoutingCall) {
        val model = verifierModel(call)
        call.respond(
            FreeMarkerContent("verifier_home.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    suspend fun showPresentationRequestPage(call: RoutingCall) {
        val model = verifierModel(call)
        model["subjects"] = issuerSvc.getCredentialUsers().map { SubjectOption.fromUserRepresentation(it) }.toList()
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
        ).withLoginContext(model.auth)

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
}
