package io.nessus.identity.config

import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addEnvironmentSource
import com.sksamuel.hoplite.addResourceSource
import kotlinx.serialization.Serializable

@OptIn(ExperimentalHoplite::class)
object ConfigProvider {

    val root = ConfigLoaderBuilder.Companion.default()
        .withExplicitSealedTypes()
        .addEnvironmentSource()
        .addResourceSource("/application.conf")
        .build().loadConfigOrThrow<RootConfig>()

    fun requireConsoleConfig(): ConsoleConfig {
        return root.console ?: error("No 'console' config")
    }

    fun requireDatabaseConfig(): DatabaseConfig {
        return root.database ?: error("No 'database' config")
    }

    fun requireEbsiConfig(): EbsiConfig {
        return root.ebsi ?: error("No 'ebsi' config")
    }

    fun requireIssuerConfig(): IssuerConfig {
        return root.issuer ?: error("No 'issuer' config")
    }

    fun requireWalletConfig(): WalletConfig {
        return root.wallet ?: error("No 'wallet' config")
    }

    fun requireVerifierConfig(): VerifierConfig {
        return root.verifier ?: error("No 'verifier' config")
    }

    fun requireWaltIdConfig(): WaltIdConfig {
        return root.waltid ?: error("No 'waltid' config")
    }

    fun requireWaltIdWalletApiConfig(): EndpointConfig {
        val waltIdCfg = requireWaltIdConfig()
        return waltIdCfg.walletApi ?: error("No 'waltid.walletApi' config")
    }
}

@Serializable
data class RootConfig(
    val version: String,
    val console: ConsoleConfig?,
    val database: DatabaseConfig?,
    val ebsi: EbsiConfig?,
    val issuer: IssuerConfig?,
    val wallet: WalletConfig?,
    val verifier: VerifierConfig?,
    val waltid: WaltIdConfig?,
)

@Serializable
data class ConsoleConfig(
    var host: String = "0.0.0.0",
    val port: Int,
    val baseUrl: String,
    val autoLogin: Boolean
)

@Serializable
data class DatabaseConfig(
    val jdbcUrl: String,
    val username: String,
    val password: String,
)

@Serializable
data class EbsiConfig(
    var host: String = "0.0.0.0",
    val port: Int,
    val baseUrl: String,
    // The Issuer needs to know the Requester's DID for the Pre-Authorized use cases
    // https://hub.ebsi.eu/wallet-conformance/issue-to-holder/flow
    val requesterDid: String?,
    val preauthorizedPin: String?,
    val userEmail: String?,
    val userPassword: String?,
)

@Serializable
data class EndpointConfig(
    var host: String = "0.0.0.0",
    val port: Int,
    val baseUrl: String,
)

@Serializable
data class IssuerConfig(
    val baseUrl: String,
    val realm: String,
    val clientId: String,
    val serviceId: String,
    val serviceSecret: String,
)

@Serializable
data class VerifierConfig(
    val baseUrl: String,
    val responseUri: String,
)

@Serializable
data class WalletConfig(
    val baseUrl: String,
    val authUrl: String,
    val redirectUri: String,
)

@Serializable
data class WaltIdConfig(
    val walletApi: EndpointConfig?,
    val demoWallet: EndpointConfig?,
    val devWallet: EndpointConfig?,
    val vcRepo: EndpointConfig?,
)
