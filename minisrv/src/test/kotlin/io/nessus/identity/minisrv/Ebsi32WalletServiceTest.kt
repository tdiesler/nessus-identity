package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService
import io.nessus.identity.types.W3CCredentialV11Jwt
import org.junit.jupiter.api.Test

class Ebsi32WalletServiceTest : AbstractWalletServiceTest() {

    override fun createIssuerService(): IssuerService {
        return IssuerService.createEbsi32()
    }

    @Test
    fun getCredentialAuthorisedDeferred() {
        runBlocking {

            val configId = "CTWalletSameAuthorisedDeferred"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    @Test
    fun getCredentialPreAuthorisedDeferred() {
        runBlocking {

            val configId = "CTWalletSamePreAuthorisedDeferred"
            val credOffer =
                issuerSvc.createCredentialOffer(configId, alice.did, preAuthorized = true, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }
}
