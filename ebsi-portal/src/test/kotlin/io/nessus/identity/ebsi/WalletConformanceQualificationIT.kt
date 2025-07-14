package io.nessus.identity.ebsi

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.support.ui.WebDriverWait
import java.time.Duration

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceQualificationIT : AbstractWalletConformanceTest() {

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
    fun testCTQualificationThroughVPExchange() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = authLogin(Max)

        // Click "Continue" button
        driver.findElement(By.xpath("//button[.//span[text()='Continue']]")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletQualificationCredential"
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
        val checkboxId = "request_ct_wallet_qualification_credential"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

}
