package io.nessus.identity.api

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.ktor.server.engine.EmbeddedServer
import io.nessus.identity.service.AbstractServiceTest
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.OIDContext
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletAPITest : AbstractServiceTest() {

    lateinit var server: EmbeddedServer<*, *>
    val issuerSrv = IssuerService.createKeycloak()
    val walletApi = WalletAPIClient()

    @BeforeAll
    fun setup() {
        server = WalletApiServer().createServer()
        server.start()
    }

    @AfterAll
    fun tearDown() {
        server.stop()
    }

    @Test
    fun testPostCredentialOffer() {
        runBlocking {

            // Issuer's OIDC context (Max is the Issuer)
            val max = OIDContext(loginWithDid(Max))

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(loginWithDid(Alice))

            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))
            val res = walletApi.receiveCredentialOffer(alice.walletId, credOffer)
            res shouldBeEqual "{}"
        }
    }
}