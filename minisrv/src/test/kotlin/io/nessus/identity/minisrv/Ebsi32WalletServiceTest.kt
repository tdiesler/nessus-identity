package io.nessus.identity.minisrv

import io.nessus.identity.service.IssuerService

class Ebsi32WalletServiceTest : AbstractWalletServiceTest() {

    override fun createIssuerService(): IssuerService {
        return IssuerService.createEbsi32()
    }
}
