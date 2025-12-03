package io.nessus.identity.waltid

import id.walt.did.dids.DidService
import io.nessus.identity.config.ConfigProvider
import kotlinx.coroutines.runBlocking

object WaltIDServiceProvider {

    val widDidService = runBlocking {
        DidService.minimalInit()
        DidService
    }

    val widWalletService = run {
        val waltidCfg = ConfigProvider.requireWaltIdConfig()
        WaltIDWalletService(waltidCfg.walletApi!!.baseUrl)
    }
}