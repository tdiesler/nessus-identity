package io.nessus.identity.service

import org.junit.jupiter.api.Test

class WalletServiceEbsi32Test : AbstractServiceTest() {

    val walletSvc = WalletService.create()
    val issuerSvc = IssuerService.createEbsi()

    @Test
    fun getCredentialFromOfferInTime() {
    }
}
