package io.nessus.identity.service

import io.kotest.matchers.shouldBe
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssueCredentialTest : AbstractServiceTest() {

    @Test
    fun issueCredential_InTime_Test() {
        runBlocking {
            val ictx = setupWalletWithDid(Max)
            ictx.hasDidInfo shouldBe true

            val hctx = setupWalletWithDid(Alice)
            hctx.hasDidInfo shouldBe true

            val sub= hctx.did
            val types = listOf("VerifiableCredential", "VerifiableAttestation", "WalletAuthorisedInTime")
            IssuerService.createCredentialOffer(ictx, sub, types)
        }
    }
}