package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService

class MiniServerBuilder {
    var issuerSvc: IssuerService? = null
    var walletSvc: WalletService? = null
    var verifierSvc: VerifierService? = null

    fun withIssuerService(issuerSvc: IssuerService): MiniServerBuilder {
        this.issuerSvc = issuerSvc
        return this
    }

    fun withWalletService(walletSvc: WalletService): MiniServerBuilder {
        this.walletSvc = walletSvc
        return this
    }

    fun withVerifierService(verifierSvc: VerifierService): MiniServerBuilder {
        this.verifierSvc = verifierSvc
        return this
    }

    fun build(): MiniServer {
        return MiniServer(
            issuerSvc ?: IssuerService.createNative(),
            walletSvc ?: WalletService.createNative(),
            verifierSvc ?: VerifierService.createNative()
        )
    }
}
