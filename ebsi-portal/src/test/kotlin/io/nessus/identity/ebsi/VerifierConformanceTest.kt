package io.nessus.identity.ebsi

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VerifierConformanceTest : AbstractConformanceTest() {

    @BeforeAll
    fun setup() {
        startPortalServer()
        prepareVerifierTests()
    }

    @AfterAll
    fun tearDown() {
        stopPortalServer()
    }

    @Test
    fun testIDTokenExchange() {

        // Click the "Validate" link
        val validateId = "verifier_id_token_exchange"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testValidCredentialInPresentation() {

        // Click the "Validate" link
        val validateId = "verifier_vp_valid_vc"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testExpiredCredentialInPresentation() {

        // Click the "Validate" link
        val validateId = "verifier_vp_expired_vc"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testRevokedCredentialInPresentation() {

        // Click the "Validate" link
        val validateId = "verifier_vp_revoked_vc"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareVerifierTests(): LoginContext {

        val ctx = authLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        driver.get("https://hub.ebsi.eu/wallet-conformance/verifier")
        nextStep()

        // Verifier Conformance Testing -> Start
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/verifier/flow']")).click()
        nextStep()

        // Enter the authUri
        driver.findElement(By.name("clientId")).sendKeys(authEndpointUri(ctx))
        log.info { "AuthUri: ${authEndpointUri(ctx)}" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        // Click the collapsible element
        driver.findElement(By.id("id-token-exchange")).click()
        nextStep()

        // Click the collapsible element
        driver.findElement(By.id("verifiable-presentations")).click()
        nextStep(2000)

        return ctx
    }
}

