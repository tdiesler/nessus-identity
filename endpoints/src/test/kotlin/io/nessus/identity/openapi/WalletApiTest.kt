package io.nessus.identity.openapi

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.ktor.server.engine.EmbeddedServer
import io.nessus.identity.service.AbstractServiceTest
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.KeycloakIssuerService
import io.nessus.identity.service.OIDContext
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletApiTest : AbstractServiceTest() {

    lateinit var server: EmbeddedServer<*, *>
    lateinit var issuerSvc: KeycloakIssuerService

    val walletApi = WalletApiClient()

    @BeforeAll
    fun setup() {
        server = WalletApiServer().createServer()
        server.start()

        runBlocking {
            val ctx = OIDContext(login(Max).withDidInfo())
            issuerSvc = IssuerService.createKeycloak(ctx)
        }
    }

    @AfterAll
    fun tearDown() {
        server.stop()
    }

    @Test
    fun testReceiveCredentialOffer() {
        runBlocking {

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(login(Alice).withDidInfo())

            val credOffer = issuerSvc.createCredentialOffer(subId = alice.did, types = listOf("oid4vc_identity_credential"))
            val res = walletApi.receiveCredentialOffer(alice.walletId, credOffer)
            res shouldBeEqual "{}"
        }
    }
}