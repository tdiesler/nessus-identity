package io.nessus.identity.ebsi

import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.common.HybridBinarizer
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.OutputType
import org.openqa.selenium.TakesScreenshot
import javax.imageio.ImageIO

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WalletConformanceCrossDeviceTest : AbstractWalletConformanceTest() {

    @BeforeAll
    fun setup() {
        startPortalServer()
        prepareWalletTests(true)
    }

    @AfterAll
    fun tearDown() {
        stopPortalServer()
    }

    @Test
    fun testCTWalletCrossAuthorisedInTime() {

        authLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("inTime-credential")).click()
        nextStep()

        val container = driver.findElement(By.id("collapsible-content-inTime-credential"))
        (driver as JavascriptExecutor).executeScript("arguments[0].scrollIntoView({block: 'start'});", container)
        nextStep()

        // Click the "Initiate" link
        val xpath = By.xpath(".//button[normalize-space()='Initiate (credential offering QR code)']")
        container.findElement(xpath).click()
        nextStep()

        // Find the first <svg> element within the container
        val svg = container.findElement(By.tagName("svg"))

        // Take a screenshot of the SVG element
        val screenshotFile = (svg as TakesScreenshot).getScreenshotAs(OutputType.FILE)

        // Load it as BufferedImage for further inspection
        val image = ImageIO.read(screenshotFile)
        println("Image dimensions: ${image.width} x ${image.height}")

        // Load image and decode with ZXing
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val result = MultiFormatReader().decode(bitmap)

        val qrContent = result.text
        println("QR Code content: $qrContent")

        // Open URL in new tab
        val originalTab = driver.windowHandle  // Save current tab
        val targetUrl = qrContent.removePrefix("openid-credential-offer://")
        (driver as JavascriptExecutor).executeScript("window.open(arguments[0], '_blank');", targetUrl)

        println("Opened URL in new tab: $targetUrl")
        nextStep()

        // Wait for the "Validate" label to become Yes
        driver.switchTo().window(originalTab)
        val checkboxId = "ct_wallet_cross_authorised_in_time"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletCrossAuthorisedDeferred() {

        authLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential")).click()
        nextStep()

        val container = driver.findElement(By.id("collapsible-content-deferred-credential"))
        (driver as JavascriptExecutor).executeScript("arguments[0].scrollIntoView({block: 'start'});", container)
        nextStep()

        // Click the "Initiate" link
        val xpath = By.xpath(".//button[normalize-space()='Initiate (credential offering QR code)']")
        container.findElement(xpath).click()
        nextStep()

        // Find the first <svg> element within the container
        val svg = container.findElement(By.tagName("svg"))

        // Take a screenshot of the SVG element
        val screenshotFile = (svg as TakesScreenshot).getScreenshotAs(OutputType.FILE)

        // Load it as BufferedImage for further inspection
        val image = ImageIO.read(screenshotFile)
        println("Image dimensions: ${image.width} x ${image.height}")

        // Load image and decode with ZXing
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val result = MultiFormatReader().decode(bitmap)

        val qrContent = result.text
        println("QR Code content: $qrContent")

        // Open URL in new tab
        val originalTab = driver.windowHandle  // Save current tab
        val targetUrl = qrContent.removePrefix("openid-credential-offer://")
        (driver as JavascriptExecutor).executeScript("window.open(arguments[0], '_blank');", targetUrl)

        println("Opened URL in new tab: $targetUrl")
        nextStep(8000)

        // Wait for the "Validate" label to become Yes
        driver.switchTo().window(originalTab)
        val checkboxId = "ct_wallet_cross_authorised_deferred"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletCrossPreAuthorisedInTime() {

        authLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-in-time-credential")).click()
        nextStep()

        val container = driver.findElement(By.id("collapsible-content-pre-auth-in-time-credential"))
        (driver as JavascriptExecutor).executeScript("arguments[0].scrollIntoView({block: 'start'});", container)
        nextStep()

        val userPin = extractUserPinCode()
        log.info { "Extracted PIN code: $userPin" }

        // Click the "Initiate" link
        val xpath = By.xpath(".//button[normalize-space()='Initiate (credential offering QR code)']")
        container.findElement(xpath).click()
        nextStep()

        // Find the first <svg> element within the container
        val svg = container.findElement(By.tagName("svg"))

        // Take a screenshot of the SVG element
        val screenshotFile = (svg as TakesScreenshot).getScreenshotAs(OutputType.FILE)

        // Load it as BufferedImage for further inspection
        val image = ImageIO.read(screenshotFile)
        println("Image dimensions: ${image.width} x ${image.height}")

        // Load image and decode with ZXing
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val result = MultiFormatReader().decode(bitmap)

        val qrContent = result.text
        println("QR Code content: $qrContent")

        // Open URL in new tab
        val originalTab = driver.windowHandle  // Save current tab
        val targetUrl = qrContent.removePrefix("openid-credential-offer://")
        (driver as JavascriptExecutor).executeScript("window.open(arguments[0], '_blank');", targetUrl)

        println("Opened URL in new tab: $targetUrl")
        nextStep()

        // Wait for the "Validate" label to become Yes
        driver.switchTo().window(originalTab)
        val checkboxId = "ct_wallet_cross_pre_authorised_in_time"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletCrossPreAuthorisedDeferred() {

        authLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-deferred-credential")).click()
        nextStep()

        val container = driver.findElement(By.id("collapsible-content-pre-auth-deferred-credential"))
        (driver as JavascriptExecutor).executeScript("arguments[0].scrollIntoView({block: 'start'});", container)
        nextStep()

        val userPin = extractUserPinCode()
        log.info { "Extracted PIN code: $userPin" }

        // Click the "Initiate" link
        val xpath = By.xpath(".//button[normalize-space()='Initiate (credential offering QR code)']")
        container.findElement(xpath).click()
        nextStep()

        // Find the first <svg> element within the container
        val svg = container.findElement(By.tagName("svg"))

        // Take a screenshot of the SVG element
        val screenshotFile = (svg as TakesScreenshot).getScreenshotAs(OutputType.FILE)

        // Load it as BufferedImage for further inspection
        val image = ImageIO.read(screenshotFile)
        println("Image dimensions: ${image.width} x ${image.height}")

        // Load image and decode with ZXing
        val source = BufferedImageLuminanceSource(image)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val result = MultiFormatReader().decode(bitmap)

        val qrContent = result.text
        println("QR Code content: $qrContent")

        // Open URL in new tab
        val originalTab = driver.windowHandle  // Save current tab
        val targetUrl = qrContent.removePrefix("openid-credential-offer://")
        (driver as JavascriptExecutor).executeScript("window.open(arguments[0], '_blank');", targetUrl)

        println("Opened URL in new tab: $targetUrl")
        nextStep(8000)

        // Wait for the "Validate" label to become Yes
        driver.switchTo().window(originalTab)
        val checkboxId = "ct_wallet_cross_pre_authorised_deferred"
        val labelResult = awaitCheckboxResult(checkboxId, "Validate")
        log.info { "Validation: " + if (labelResult) "Yes" else "No" }

        labelResult.shouldBeTrue()
    }

    // Private -------------------------------------------------------------------------------------------------------
}
