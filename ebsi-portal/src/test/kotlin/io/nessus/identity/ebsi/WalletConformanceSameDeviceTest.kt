package io.nessus.identity.ebsi

import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceSameDeviceTest : AbstractWalletConformanceTest() {

    @BeforeAll
    fun setup() {
        startNessusServer()
        startPlaywrightBrowser()
        prepareWalletTests(false)
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopNessusServer()
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        val ctype = "CTWalletSameAuthorisedInTime"
        log.info { ">>>>> Wallet $ctype" }

        val ctx = login(Max)

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#inTime-credential-same-device")

        // Click the "Initiate" link
        val link = page.locator("a[href*='credential_type=$ctype']").first()
        fixupInitiateHref(ctx, link)

        // Wait for the new tab to open
        val newPage = page.context().waitForPage { link.click() }
        log.info { "Switched to new tab" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "InTime Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Close new tab and switch back to original
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_authorised_in_time"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        val ctype = "CTWalletSameAuthorisedDeferred"
        log.info { ">>>>> Wallet $ctype" }

        val ctx = login(Max)

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#deferred-credential-same-device")

        // Click the "Initiate" link
        val link = page.locator("a[href*='credential_type=$ctype']").first()
        fixupInitiateHref(ctx, link)

        // Wait for the new tab to open
        val newPage = page.context().waitForPage { link.click() }
        log.info { "Switched to new tab" }

        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "Deferred Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Close new tab and switch back to original
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_authorised_deferred"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        val ctype = "CTWalletSamePreAuthorisedInTime"
        log.info { ">>>>> Wallet $ctype" }

        val ctx = login(Max)

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-in-time-credential-same-device")

        val userPin = extractUserPin(page)
        log.info { "Pre-Auth user PIN: $userPin" }
        putCredentialOfferRecord(ctype, null, userPin)

        // Click the "Initiate" link
        val link = page.locator("a[href*='credential_type=$ctype']").first()
        fixupInitiateHref(ctx, link)

        // Wait for the new tab to open
        val newPage = page.context().waitForPage { link.click() }
        log.info { "Switched to new tab" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "PreAuthorised Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Close new tab and switch back to original
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_pre_authorised_in_time"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletSamePreAuthorisedDeferred() {

        val ctype = "CTWalletSamePreAuthorisedDeferred"
        log.info { ">>>>> Wallet $ctype" }

        val ctx = login(Max)

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-deferred-credential-same-device")

        val userPin = extractUserPin(page)
        log.info { "Pre-Auth user PIN: $userPin" }
        putCredentialOfferRecord(ctype, null, userPin)

        // Click the "Initiate" link
        val link = page.locator("a[href*='credential_type=$ctype']").first()
        fixupInitiateHref(ctx, link)

        // Wait for the new tab to open
        val newPage = page.context().waitForPage { link.click() }
        log.info { "Switched to new tab" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "PreAuthorised Deferred Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Close new tab and switch back to original
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_pre_authorised_deferred"
        assertCheckboxResult(page, checkboxId, "Validate")
    }
}
