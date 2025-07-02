package io.nessus.identity.portal

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebElement
import org.openqa.selenium.support.ui.WebDriverWait
import java.net.URI
import java.net.URLEncoder
import java.time.Duration

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceSameDeviceTest : AbstractWalletConformanceTest() {

    @BeforeAll
    fun setup() {
        startPortalServer()
        prepareWalletTests(false)
    }

    @AfterAll
    fun tearDown() {
        stopPortalServer()
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("inTime-credential-same-device")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSameAuthorisedInTime"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep()

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_authorised_in_time"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential-same-device")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSameAuthorisedDeferred"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "Deferred Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep(5000)

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_authorised_deferred"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-in-time-credential-same-device")).click()
        nextStep()

        val userPin = extractUserPinCode()
        log.info { "Extracted PIN code: $userPin" }

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSamePreAuthorisedInTime"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "PreAuthorised Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep()

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_pre_authorised_in_time"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSamePreAuthorisedDeferred() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-deferred-credential-same-device")).click()
        nextStep()

        val userPin = extractUserPinCode()
        log.info { "Extracted PIN code: $userPin" }

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSamePreAuthorisedDeferred"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "PreAuthorised Deferred Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep(5000)

        // Wait for the "Validate" label to become Yes
        val checkboxId = "ct_wallet_same_pre_authorised_deferred"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun fixupInitiateHref(ctx: LoginContext, link: WebElement): WebElement {

        val walletUri = walletEndpointUri(ctx)
        var initiateHref = link.getAttribute("href") as String
        log.info { "Initiate href: $initiateHref" }

        val uri = URI(initiateHref)
        val queryParams = urlQueryToMap(initiateHref).toMutableMap()
        val encodedWalletUri = URLEncoder.encode(walletUri, "UTF-8")

        if (queryParams["credential_offer_endpoint"] != encodedWalletUri) {
            queryParams["credential_offer_endpoint"] = encodedWalletUri

            val updatedQuery = queryParams.entries.joinToString("&") { (k, v) -> "$k=$v" }
            initiateHref = "${uri.scheme}://${uri.authority}${uri.path}?$updatedQuery"

            log.info { "Overriding with: $initiateHref" }

            (driver as JavascriptExecutor).executeScript(
                "arguments[0].setAttribute('href', arguments[1])",
                link, initiateHref
            )
        }
        return link
    }
}
