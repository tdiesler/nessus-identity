package io.nessus.identity.console

import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWaltIdConfig
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*

class EBSIHandler() {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    fun ebsiModel(call: RoutingCall): BaseModel {
        val ebsiConfig = requireEbsiConfig()
        val waltIdConfig = requireWaltIdConfig()
        val model = BaseModel()
            .withLoginContext(call, UserRole.Holder)
            .withLoginContext(call, UserRole.Issuer)
            .withLoginContext(call, UserRole.Verifier)
        val holder = model.loginContexts[UserRole.Holder] as LoginContext
        val issuer = model.loginContexts[UserRole.Issuer] as LoginContext
        val verifier = model.loginContexts[UserRole.Verifier] as LoginContext
        if (holder.hasAuthToken) {
            model["walletName"] = holder.walletInfo.name
            model["walletDid"] = holder.didInfo.did
            model["walletUri"] = "${ebsiConfig.baseUrl}/wallet/${holder.targetId}"
            model["issuerUri"] = "${ebsiConfig.baseUrl}/issuer/${holder.targetId}"
        }
        if (issuer.hasAuthToken) {
            model["issuerName"] = issuer.walletInfo.name
            model["issuerDid"] = issuer.didInfo.did
            model["issuerUri"] = "${ebsiConfig.baseUrl}/issuer/${issuer.targetId}"
        }
        if (verifier.hasAuthToken) {
            model["verifierName"] = verifier.walletInfo.name
            model["verifierDid"] = verifier.didInfo.did
            model["verifierUri"] = "${ebsiConfig.baseUrl}/verifier/${verifier.targetId}"
        }
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
