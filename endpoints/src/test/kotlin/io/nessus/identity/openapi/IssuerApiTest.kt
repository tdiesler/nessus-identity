package io.nessus.identity.openapi

import io.kotest.common.runBlocking
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
class IssuerApiTest : AbstractServiceTest() {

    lateinit var server: EmbeddedServer<*, *>
    val issuerApi = IssuerApiClient()

    @BeforeAll
    fun setup() {
        server = IssuerApiServer().create()
        server.start()
    }

    @AfterAll
    fun tearDown() {
        server.stop()
    }

    @Test
    fun testCreateCredentialOffer() {
        runBlocking {

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(login(Alice).withDidInfo())

            val credOffer = issuerApi.createCredentialOffer(alice.did, listOf("oid4vc_identity_credential"))
            credOffer.shouldNotBeNull()
        }
    }
}