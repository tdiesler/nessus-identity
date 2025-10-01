package io.nessus.identity.waltid

import io.nessus.identity.config.ConfigProvider

object WaltIDServiceProvider {

    val widWalletSvc = run {
        val waltidCfg = ConfigProvider.requireWaltIdConfig()
        WaltIDWalletService(waltidCfg.walletApi!!.baseUrl)
    }
}