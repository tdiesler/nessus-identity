package io.nessus.identity.openapi

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.ktor.server.engine.EmbeddedServer
import io.nessus.identity.service.AbstractServiceTest
import io.nessus.identity.service.OIDContext
import io.nessus.identity.waltid.Alice
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletApiTest : AbstractServiceTest() {

    lateinit var issuerApiSrv: EmbeddedServer<*, *>
    lateinit var walletApiSrv: EmbeddedServer<*, *>

    val issuer = IssuerApiClient()
    val wallet = WalletApiClient()

    @BeforeAll
    fun setup() {
        issuerApiSrv = IssuerApiServer().create().start()
        walletApiSrv = WalletApiServer().create().start()
    }

    @AfterAll
    fun tearDown() {
        walletApiSrv.stop()
        issuerApiSrv.stop()
    }

    @Test
    fun testReceiveCredentialOffer() {
        runBlocking {

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(login(Alice).withDidInfo())

            val ctype = "oid4vc_identity_credential"

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
            val credOffer = issuer.createCredentialOffer(alice.did, listOf(ctype))
            val credOfferId = wallet.receiveCredentialOffer(alice.walletId, credOffer)

        }
    }
}