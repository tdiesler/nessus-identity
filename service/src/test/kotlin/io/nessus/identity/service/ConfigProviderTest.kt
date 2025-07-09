package io.nessus.identity.service

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.nessus.identity.config.ConfigProvider
import org.junit.jupiter.api.Test

class ConfigProviderTest {

    @Test
    fun loadConfig() {

        val holder = ConfigProvider.requireWalletConfig()
        val service = ConfigProvider.requireServiceConfig()
        val database = ConfigProvider.requireDatabaseConfig()

        holder.userEmail.shouldNotBeBlank()
        holder.userPassword.shouldNotBeBlank()

        service.walletApiUrl shouldBe "http://localhost:7001"

        database.jdbcUrl.shouldNotBeBlank()
    }
}
