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

    fun requireDatabaseConfig(): DatabaseConfig {
        return root.database ?: throw IllegalStateException("No 'database' config")
    }

    fun requireEbsiConfig(): EbsiConfig {
        return root.ebsi ?: throw IllegalStateException("No 'ebsi' config")
    }

    fun requireIssuerConfig(): IssuerConfig {
        return root.issuer ?: throw IllegalStateException("No 'issuer' config")
    }

    fun requireIssuerApiConfig(): EndpointConfig {
        return root.issuerApi ?: throw IllegalStateException("No 'issuerApi' config")
    }

    fun requireWalletApiConfig(): EndpointConfig {
        return root.walletApi ?: throw IllegalStateException("No 'walletApi' config")
    }

    fun requireWaltIdConfig(): WaltIdConfig {
        return root.waltid ?: throw IllegalStateException("No 'waltid' config")
    }

    fun requireWaltIdWalletApiConfig(): EndpointConfig {
        val waltIdCfg = requireWaltIdConfig()
        return waltIdCfg.walletApi ?: throw IllegalStateException("No 'waltid.walletApi' config")
    }
}

@Serializable
data class RootConfig(
    val version: String,
    val console: EndpointConfig?,
    val database: DatabaseConfig?,
    val ebsi: EbsiConfig?,
    val issuer: IssuerConfig?,
    val issuerApi: EndpointConfig?,
    val walletApi: EndpointConfig?,
    val waltid: WaltIdConfig?,
)

@Serializable
data class EndpointConfig(
    var host: String = "0.0.0.0",
    val port: Int,
    val baseUrl: String,
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
data class DatabaseConfig(
    val jdbcUrl: String,
    val username: String,
    val password: String,
)

@Serializable
data class IssuerConfig(
    val baseUrl: String,
    val clientId: String,
)

@Serializable
data class WaltIdConfig(
    val walletApi: EndpointConfig?,
    val demoWallet: EndpointConfig?,
    val devWallet: EndpointConfig?,
    val vcRepo: EndpointConfig?,
)
