package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.ConfigProvider.requireWaltIdConfig
import io.nessus.identity.console.SessionsStore.findLoginContext
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*

class EBSIHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    fun ebsiModel(call: RoutingCall): BaseModel {
        val ebsiConfig = requireEbsiConfig()
        val issuerConfig = requireIssuerConfig()
        val waltIdConfig = requireWaltIdConfig()
        val model = BaseModel().withLoginContext(call, UserRole.Holder)
        findLoginContext(call, UserRole.Holder)?.also {
            model["holderName"] = it.walletInfo.name
            model["holderDid"] = it.didInfo.did
            model["walletUri"] = "${ebsiConfig.baseUrl}/wallet/${it.targetId}"
            model["issuerUri"] = "${issuerConfig.baseUrl}/realms/${issuerConfig.realm}"
            model["verifierUri"] = "${ebsiConfig.baseUrl}/verifier/${it.targetId}"
            model["demoWalletUrl"] = "${waltIdConfig.demoWallet?.baseUrl}"
        }
        return model
    }

    suspend fun showHome(call: RoutingCall) {
        val model = ebsiModel(call)
        call.respond(
            FreeMarkerContent("ebsi_home.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}
