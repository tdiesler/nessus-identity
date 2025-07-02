package io.nessus.identity.portal

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.Max
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebElement
import java.net.URI
import java.net.URLEncoder

abstract class AbstractWalletConformanceTest : AbstractConformanceTest() {

    fun prepareWalletTests(crossDevive: Boolean): LoginContext {

        val ctx = userLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        driver.get("https://hub.ebsi.eu/wallet-conformance")
        nextStep()

        // Request and present Verifiable Credentials -> Start tests
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/holder-wallet']")).click()
        nextStep()

        // Holder Wallet Conformance Testing -> Start
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/holder-wallet/flow?step=0']")).click()
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[.//span[text()='Continue']]")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("did")).sendKeys(ctx.did)
        log.info { "DID: ${ctx.did}" }
        nextStep()

        // Enter the walletUri
        driver.findElement(By.name("credential_offer_endpoint")).sendKeys(walletEndpointUri(ctx))
        log.info { "WalletUri: ${walletEndpointUri(ctx)}" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        // QR reading capabilities
        if (crossDevive) {
            driver.findElement(By.xpath("//button[text()='Yes']")).click()
        } else {
            driver.findElement(By.xpath("//button[text()='No']")).click()
        }
        nextStep()

        return ctx
    }
}
