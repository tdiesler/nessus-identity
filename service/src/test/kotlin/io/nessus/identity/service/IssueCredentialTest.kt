package io.nessus.identity.service

import io.kotest.matchers.shouldBe
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssueCredentialTest : AbstractServiceTest() {

    /**
     * Issue Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows
     *
     * - Holder sends an Authorisation Request to the Issuer's Authorisation Server (IAuth)
     * - IAuth validates the request and requests authentication of a DID from the client
     * - Holder issues an ID Token signed by the DID's authentication key (prove control of the DID)
     * - Holder calls the IAuth's Token Endpoint to obtain an Access Token
     * - IAuth validates the request and responds with an Access Token
     * - Holder sends the Credential Request
     */
    @Test
    fun issueCredentialInTime() {
        runBlocking {
            val ictx = setupWalletWithDid(Max)
            ictx.hasDidInfo shouldBe true

            val hctx = setupWalletWithDid(Alice)
            hctx.hasDidInfo shouldBe true

            val sub= hctx.did
            val types = listOf("TestCredential")
            IssuerService.createCredentialOffer(ictx, sub, types)
        }
    }
}