package io.nessus.identity.console

import io.ktor.server.freemarker.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWaltIdConfig
import io.nessus.identity.service.Ebsi32IssuerService
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.UserRole
import kotlinx.serialization.json.*

class EBSIHandler(
    val issuerSvc: IssuerService, // Keycloak Issuer
    val walletSvc: WalletService,
    val verifierSvc: VerifierService
) {

    val ebsiIssuerService = Ebsi32IssuerService()

    val jsonPretty = Json { prettyPrint = true }

    suspend fun ebsiModel(call: RoutingCall): BaseModel {
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
            model["walletUri"] = "${walletSvc.endpointUri}/${holder.targetId}"
        }
        if (issuer.hasAuthToken) {
            model["issuerName"] = issuer.walletInfo.name
            model["issuerDid"] = issuer.didInfo.did
            model["issuerUri"] = "${issuerSvc.endpointUri}/${issuer.targetId}"
        }
        if (verifier.hasAuthToken) {
            model["verifierName"] = verifier.walletInfo.name
            model["verifierDid"] = verifier.didInfo.did
            model["verifierUri"] = "${verifierSvc.endpointUri}/${verifier.targetId}"
        }
        val issuerMetadata = ebsiIssuerService.getIssuerMetadata() as IssuerMetadataDraft11
        val authMetadataUrl = issuerMetadata.authorizationServer as String
        val issuerMetadataUrl = ebsiIssuerService.getIssuerMetadataUrl()
        model["authMetadataUrl"] = authMetadataUrl
        model["issuerMetadataUrl"] = issuerMetadataUrl
        model["demoWalletUrl"] = "${waltIdConfig.demoWallet?.baseUrl}"
        return model
    }

    suspend fun showHome(call: RoutingCall) {
        val model = ebsiModel(call)
        call.respond(
            FreeMarkerContent("ebsi_home.ftl", model)
        )
    }

    suspend fun showAuthMetadata(call: RoutingCall) {
        val model = ebsiModel(call).also {
            it["authMetadataJson"] = let {
                val issuerMetadata = ebsiIssuerService.getIssuerMetadata()
                val authMetadata = issuerMetadata.getAuthorizationMetadata()
                jsonPretty.encodeToString(authMetadata)
            }
        }
        call.respond(
            FreeMarkerContent("ebsi_auth_metadata.ftl", model)
        )
    }

    suspend fun showIssuerMetadata(call: RoutingCall) {
        val model = ebsiModel(call).also {
            it["issuerMetadataJson"] = let {
                val issuerMetadata = ebsiIssuerService.getIssuerMetadata()
                jsonPretty.encodeToString(issuerMetadata)
            }
        }
        call.respond(
            FreeMarkerContent("ebsi_issuer_metadata.ftl", model)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}
