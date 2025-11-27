package io.nessus.identity.ebsi

import io.nessus.identity.waltid.Alice
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceQualificationIT : AbstractWalletConformanceTest() {

    @BeforeAll
    fun setup() {
        startConsoleServer()
        startPlaywrightBrowser()
        prepareWalletTests(false)
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopConsoleServer()
    }

    @Test
    fun testCTQualificationThroughVPExchange() {

        val ctype = "CTWalletQualificationCredential"
        log.info { ">>>>> CTQualificationThroughVPExchange" }

        val ctx = login(Alice)

        // Click "Continue" button
        val page = context.pages().last()
        page.click("xpath=//button[.//span[text()='Continue']]")

        // Click the "Initiate" link
        val link = page.locator("a[href*='credential_type=$ctype']").first()
        fixupInitiateHref(ctx, link)

        // Wait for the new tab to open
        val newPage = page.context().waitForPage { link.click() }
        log.info { "Switched to new tab" }

        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Close new tab and switch back to original
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "request_ct_wallet_qualification_credential"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    // Private ---------------------------------------------------------------------------------------------------------

}
