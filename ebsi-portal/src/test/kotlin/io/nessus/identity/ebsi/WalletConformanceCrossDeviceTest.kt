package io.nessus.identity.ebsi

import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.microsoft.playwright.Locator
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceCrossDeviceTest : AbstractWalletConformanceTest() {


    @BeforeAll
    fun setup() {
        startNessusServer()
        startPlaywrightBrowser()
        prepareWalletTests(true)
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopNessusServer()
    }

    @Test
    fun testCTWalletCrossAuthorisedInTime() {

        val ctype = "CTWalletCrossAuthorisedInTime"
        log.info { ">>>>> Wallet $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#inTime-credential")

        // Scroll container into view
        val container = page.locator("#collapsible-content-inTime-credential")
        container.scrollIntoViewIfNeeded()

        // Open decoded URL in a new tab
        val targetUrl = getQRCodeLink(container).removePrefix("openid-credential-offer://")
        val newPage = page.context().newPage()
        newPage.navigate(targetUrl)
        log.info {"Opened URL in new tab: $targetUrl" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "InTime Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Switch back to main tab (original page)
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_cross_authorised_in_time"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletCrossAuthorisedDeferred() {

        val ctype = "CTWalletCrossAuthorisedDeferred"
        log.info { ">>>>> Wallet $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#deferred-credential")

        // Scroll container into view
        val container = page.locator("#collapsible-content-deferred-credential")
        container.scrollIntoViewIfNeeded()

        // Open decoded URL in a new tab
        val targetUrl = getQRCodeLink(container).removePrefix("openid-credential-offer://")
        val newPage = page.context().newPage()
        newPage.navigate(targetUrl)
        log.info {"Opened URL in new tab: $targetUrl" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "Deferred Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Switch back to main tab (original page)
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_cross_authorised_deferred"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletCrossPreAuthorisedInTime() {

        val ctype = "CTWalletCrossPreAuthorisedInTime"
        log.info { ">>>>> Wallet $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-in-time-credential")

        // Scroll container into view
        val container = page.locator("#collapsible-content-pre-auth-in-time-credential")
        container.scrollIntoViewIfNeeded()

        val userPin = extractUserPin(page)
        log.info { "Pre-Auth user PIN: $userPin" }
        putCredentialOfferRecord(ctype, null, userPin)

        // Open decoded URL in a new tab
        val targetUrl = getQRCodeLink(container).removePrefix("openid-credential-offer://")
        val newPage = page.context().newPage()
        newPage.navigate(targetUrl)
        log.info {"Opened URL in new tab: $targetUrl" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "PreAuthorised InTime Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Switch back to main tab (original page)
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_cross_pre_authorised_in_time"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    @Test
    fun testCTWalletCrossPreAuthorisedDeferred() {

        val ctype = "CTWalletCrossPreAuthorisedDeferred"
        log.info { ">>>>> Wallet $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-deferred-credential")

        // Scroll container into view
        val container = page.locator("#collapsible-content-pre-auth-deferred-credential")
        container.scrollIntoViewIfNeeded()

        val userPin = extractUserPin(page)
        log.info { "Pre-Auth user PIN: $userPin" }
        putCredentialOfferRecord(ctype, null, userPin)

        // Open decoded URL in a new tab
        val targetUrl = getQRCodeLink(container).removePrefix("openid-credential-offer://")
        val newPage = page.context().newPage()
        newPage.navigate(targetUrl)
        log.info {"Opened URL in new tab: $targetUrl" }

        // Get the credential JSON from <pre>
        val pre = newPage.locator("pre").also { it.waitFor() }
        val credentialJson = pre.innerText()
        log.info { "PreAuthorised Deferred Credential: $credentialJson" }

        // Verify received credential
        verifyCredential(ctype, credentialJson)

        // Switch back to main tab (original page)
        newPage.close()
        page.bringToFront()
        log.info { "Switched back to main tab" }

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_cross_pre_authorised_deferred"
        assertCheckboxResult(page, checkboxId, "Validate")
    }

    // Private -------------------------------------------------------------------------------------------------------

    private fun getQRCodeLink(container: Locator): String {

        // Click the "Initiate" button inside container
        container.locator("button:has-text('Initiate (credential offering QR code)')").click()

        // Locate the first <svg> element (QR code) and screenshot it
        val svg = container.locator("svg").first()
        val screenshotBytes = svg.screenshot()

        // Load it as BufferedImage for ZXing
        val image = ImageIO.read(ByteArrayInputStream(screenshotBytes))
        log.info { "Image dimensions: ${image.width} x ${image.height}" }

        // Decode QR with ZXing
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val result = MultiFormatReader().decode(bitmap)

        val qrLink = result.text
        log.info { "QR Code: $qrLink" }
        return qrLink
    }
}
