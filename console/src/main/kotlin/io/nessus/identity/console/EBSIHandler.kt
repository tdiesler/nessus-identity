package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.ConfigProvider.requireWaltIdConfig
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*

class EBSIHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    fun ebsiModel(call: RoutingCall): BaseModel {
        val ebsiConfig = requireEbsiConfig()
        val issuerConfig = requireIssuerConfig()
        val waltIdConfig = requireWaltIdConfig()
        val model = BaseModel()
            .withLoginContext(call, UserRole.Holder)
            .withLoginContext(call, UserRole.Verifier)
        val holder = model.loginContexts[UserRole.Holder] as LoginContext
        val verifier = model.loginContexts[UserRole.Verifier] as LoginContext
        model["walletName"] = holder.walletInfo.name
        model["walletDid"] = holder.didInfo.did
        model["walletUri"] = "${ebsiConfig.baseUrl}/wallet/${holder.targetId}"
        model["issuerUri"] = "${issuerConfig.baseUrl}/realms/${issuerConfig.realm}"
        model["verifierUri"] = "${ebsiConfig.baseUrl}/verifier/${verifier.targetId}"
        model["demoWalletUrl"] = "${waltIdConfig.demoWallet?.baseUrl}"
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
