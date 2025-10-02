package io.nessus.identity.service

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.nessus.identity.config.ConfigProvider
import org.junit.jupiter.api.Test

class ConfigProviderTest {

    @Test
    fun loadConfig() {

        val database = ConfigProvider.requireDatabaseConfig()
        database.jdbcUrl.shouldNotBeBlank()

        val walletConfig = ConfigProvider.requireWalletConfig()
        walletConfig.baseUrl shouldBe "http://localhost:9000/wallet"

        val issuerConfig = ConfigProvider.requireIssuerConfig()
        issuerConfig.baseUrl shouldBe "https://oauth.localtest.me/realms/oid4vci"

        val waltIdWalletApiConfig = ConfigProvider.requireWaltIdWalletApiConfig()
        waltIdWalletApiConfig.baseUrl shouldBe "https://waltid-wallet-api.localtest.me"
    }
}
