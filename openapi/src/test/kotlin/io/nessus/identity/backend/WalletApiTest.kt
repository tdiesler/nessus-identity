package io.nessus.identity.backend

import io.kotest.common.runBlocking
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
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
    fun testAddCredentialOffer() {
        runBlocking {

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(login(Alice).withDidInfo())
            val wallet = WalletApiClient(alice)
            val walletId = alice.walletId

            val ctype = "oid4vc_identity_credential"

            // The Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
            val credOffer = issuer.createCredentialOffer(alice.did, listOf(ctype))
            val offerId = wallet.addCredentialOffer(credOffer)
            offerId.shouldNotBeNull()

            val offers = wallet.listCredentialOffers()
            offers[0].credentialConfigurationIds.shouldContain(ctype)
        }
    }

    @Test
    fun testFetchCredentialFromOffer() {
        runBlocking {

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(login(Alice).withDidInfo())
            val wallet = WalletApiClient(alice)
            val walletId = alice.walletId

            val ctype = "oid4vc_identity_credential"

            // The Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
            val credOffer = issuer.createCredentialOffer(alice.did, listOf(ctype))
            val offerId = wallet.addCredentialOffer(credOffer)

            // The Holder fetches the Credential from the Issuer for the given CredentialOffer id
            // Uses the in-time authorization flow
            val credObj = wallet.fetchCredentialFromOffer(offerId)
            credObj.shouldNotBeNull()
        }
    }
}