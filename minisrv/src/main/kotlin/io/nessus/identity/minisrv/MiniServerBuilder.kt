package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NoopIssuerService
import io.nessus.identity.service.NoopVerifierService
import io.nessus.identity.service.NoopWalletService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService

class MiniServerBuilder {

    var issuerSvc: IssuerService = NoopIssuerService()
    var walletSvc: WalletService = NoopWalletService()
    var verifierSvc: VerifierService = NoopVerifierService()
    var sessionStore: SessionStore = BasicSessionStore()

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

    fun withSessionsStore(sessionStore: SessionStore): MiniServerBuilder {
        this.sessionStore = sessionStore
        return this
    }

    fun build(): MiniServer {
        return MiniServer(issuerSvc, walletSvc, verifierSvc, sessionStore)
    }
}
