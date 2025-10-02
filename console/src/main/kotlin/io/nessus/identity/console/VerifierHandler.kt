package io.nessus.identity.console

import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.response.respond
import io.ktor.server.response.respondRedirect
import io.ktor.server.routing.RoutingCall
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.PlaywrightAuthCallbackHandler
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.collections.component1
import kotlin.collections.component2

class VerifierHandler(val verifier: User) {

    val jsonPretty = Json { prettyPrint = true }

    suspend fun handleVerifierHome(call: RoutingCall) {
        call.respond(
            FreeMarkerContent("verifier-home.ftl", null)
        )
    }}