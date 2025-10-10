package io.nessus.identity.console

import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.service.getVersionInfo
import io.nessus.identity.waltid.User
import kotlinx.serialization.json.Json

class VerifierHandler(val verifier: User) {

    val jsonPretty = Json { prettyPrint = true }

    fun verifierModel(): MutableMap<String, Any> {
        val versionInfo = getVersionInfo()
        return mutableMapOf(
            "versionInfo" to versionInfo,
        )
    }

    suspend fun handleVerifierHome(call: RoutingCall) {
        val model = verifierModel()
        call.respond(
            FreeMarkerContent("verifier-home.ftl", model)
        )
    }}