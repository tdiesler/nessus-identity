package io.nessus.identity.service

object ServiceProvider {

    val walletService = run {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        WalletService(serviceConfig.walletApiUrl)
    }
}