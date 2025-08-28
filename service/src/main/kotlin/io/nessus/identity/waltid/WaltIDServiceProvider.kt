package io.nessus.identity.waltid

import io.nessus.identity.config.ConfigProvider

object WaltIDServiceProvider {

    val widWalletSvc = run {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        WaltIDWalletService(serviceConfig.walletApiUrl)
    }
}