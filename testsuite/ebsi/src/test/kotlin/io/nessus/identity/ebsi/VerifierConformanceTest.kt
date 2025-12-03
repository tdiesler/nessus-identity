package io.nessus.identity.ebsi

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VerifierConformanceTest : AbstractVerifierConformanceTest() {

    @BeforeAll
    fun setup() {
        startMiniServer()
        startPlaywrightBrowser()
        prepareVerifierTests()
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopMiniServer()
    }

    @Test
    fun testVerifierIDTokenExchange() {

        log.info { ">>>>> VerifierIDTokenExchange" }

        // Click the "Validate" link
        val page = context.pages().last()
        val validateId = "verifier_id_token_exchange"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testVerifierValidCredentialInPresentation() {

        log.info { ">>>>> VerifierValidCredentialInPresentation" }

        // Click the "Validate" link
        val page = context.pages().last()
        val validateId = "verifier_vp_valid_vc"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testVerifierExpiredCredentialInPresentation() {

        log.info { ">>>>> VerifierExpiredCredentialInPresentation" }

        // Click the "Validate" link
        val page = context.pages().last()
        val validateId = "verifier_vp_expired_vc"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testVerifierRevokedCredentialInPresentation() {

        log.info { ">>>>> VerifierRevokedCredentialInPresentation" }

        // Click the "Validate" link
        val page = context.pages().last()
        val validateId = "verifier_vp_revoked_vc"
        assertCheckboxResult(page, validateId, "Validate")
    }
}

