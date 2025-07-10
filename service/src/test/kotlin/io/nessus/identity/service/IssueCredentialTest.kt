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
            val issuerCtx = setupWalletWithDid(Max)
            issuerCtx.hasDidInfo shouldBe true

            val holderCtx = setupWalletWithDid(Alice)
            holderCtx.hasDidInfo shouldBe true
        }
    }
}