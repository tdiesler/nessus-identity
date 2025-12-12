package io.nessus.identity.console

import io.nessus.identity.config.ConfigProvider.requireConsoleConfig
import io.nessus.identity.config.ConsoleConfig
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService

class ConsoleServerBuilder {

    var config: ConsoleConfig? = null
    var issuerSvc: IssuerService? = null
    var walletSvc: WalletService? = null
    var verifierSvc: VerifierService? = null

    fun withConsoleConfig(config: ConsoleConfig): ConsoleServerBuilder {
        this.config = config
        return this
    }

    fun withIssuerService(issuerSvc: IssuerService): ConsoleServerBuilder {
        this.issuerSvc = issuerSvc
        return this
    }

    fun withWalletService(walletSvc: WalletService): ConsoleServerBuilder {
        this.walletSvc = walletSvc
        return this
    }

    fun withVerifierService(verifierSvc: VerifierService): ConsoleServerBuilder {
        this.verifierSvc = verifierSvc
        return this
    }

    fun build(): ConsoleServer {
        return ConsoleServer(
            config ?: requireConsoleConfig(),
            issuerSvc ?: IssuerService.createKeycloak(),
            walletSvc ?: WalletService.createNative(),
            verifierSvc ?: VerifierService.createNative()
        )
    }
}
