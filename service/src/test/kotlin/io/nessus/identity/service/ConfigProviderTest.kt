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

        val walletApiConfig = ConfigProvider.requireWalletApiConfig()
        walletApiConfig.baseUrl shouldBe "http://localhost:8001"

        val issuerApiConfig = ConfigProvider.requireIssuerApiConfig()
        issuerApiConfig.baseUrl shouldBe "http://localhost:8002"

        val waltIdWalletApiConfig = ConfigProvider.requireWaltIdWalletApiConfig()
        waltIdWalletApiConfig.baseUrl shouldBe "https://waltid-wallet-api.localtest.me"
    }
}
