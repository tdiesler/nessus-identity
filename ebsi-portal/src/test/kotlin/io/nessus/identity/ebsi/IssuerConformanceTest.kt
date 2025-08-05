package io.nessus.identity.ebsi

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerConformanceTest : AbstractConformanceTest() {

    val userPin = IssuerService.defaultUserPin

    @BeforeAll
    fun setup() {
        startPortalServer()
        prepareIssuerTests()
    }

    @AfterAll
    fun tearDown() {
        stopPortalServer()
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        val ctype = "CTWalletSameAuthorisedInTime"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        driver.findElement(By.id("in-time-credential")).click()
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_in_time"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctype Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_in_time"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctype Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        val ctype = "CTWalletSameAuthorisedDeferred"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential")).click()
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_deferred"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctype Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_deferred"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctype Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        val ctype = "CTWalletSamePreAuthorisedInTime"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-in-time-credential")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("userPinInTime")).sendKeys(userPin)
        log.info { "Pre-Auth user PIN: $userPin" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("preAuthorizedCodeInTime")).sendKeys(ctype)
        log.info { "PreAuthorized Code: $ctype" }
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_in_time"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctype Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_in_time"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctype Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()

    }

    @Test
    fun testCTWalletSamePreAuthorisedDeferred() {

        val ctype = "CTWalletSamePreAuthorisedDeferred"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-deferred-credential")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("userPinDeferred")).sendKeys(userPin)
        log.info { "UserPIN: $userPin" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("preAuthorizedCodeDeferred")).sendKeys(ctype)
        log.info { "PreAuthorized Code: $ctype" }
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_deferred"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctype Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_deferred"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctype Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareIssuerTests(): LoginContext {

        val ctx = authLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        driver.get("https://hub.ebsi.eu/wallet-conformance/issue-to-holder")
        nextStep()

        // Issue Verifiable Credentials to Holder -> Start tests
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/issue-to-holder/flow']")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("did")).sendKeys(ctx.did)
        log.info { "DID: ${ctx.did}" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("clientId")).sendKeys(issuerEndpointUri(ctx))
        log.info { "IssuerUri: ${issuerEndpointUri(ctx)}" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        return ctx
    }
}
