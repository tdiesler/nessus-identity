package io.nessus.identity.ebsi

import io.kotest.common.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VerifierConformanceTest : AbstractConformanceTest() {

    @BeforeAll
    fun setup() {
        startNessusServer()
        startPlaywrightBrowser()
        prepareVerifierTests()
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopNessusServer()
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

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareVerifierTests(): LoginContext {

        val ctx = runBlocking { loginWithDid(Max) }
        ctx.hasDidInfo.shouldBeTrue()

        val page = context.newPage()
        page.navigate("https://hub.ebsi.eu/wallet-conformance/verifier")

        // Verifier Conformance Testing -> Start
        page.click("a[href='/wallet-conformance/verifier/flow']")

        // Enter the authUri
        page.fill("input[name='clientId']", authEndpointUri(ctx))
        log.info { "AuthUri: ${authEndpointUri(ctx)}" }

        // Click "Continue" button
        page.click("xpath=//button[@type='submit'][.//span[text()='Continue']]")

        // Click the collapsible element
        page.click("#id-token-exchange")

        // Click the collapsible element
        page.click("#verifiable-presentations")

        return ctx
    }
}

