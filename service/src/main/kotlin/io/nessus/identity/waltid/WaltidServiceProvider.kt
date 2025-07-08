package io.nessus.identity.waltid

import io.nessus.identity.config.ConfigProvider

object WaltidServiceProvider {

    val widWalletSvc = run {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        WaltidWalletService(serviceConfig.walletApiUrl)
    }
}