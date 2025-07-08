package io.nessus.identity.ebsi

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.UserPinHolder
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerConformanceTest : AbstractConformanceTest() {

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

        // Click the collapsible element
        driver.findElement(By.id("in-time-credential")).click()
        nextStep()

        val ctType = "CTWalletSameAuthorisedInTime"

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_in_time"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctType Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_in_time"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctType Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential")).click()
        nextStep()

        val ctType = "CTWalletSameAuthorisedDeferred"

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_deferred"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctType Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_deferred"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctType Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-in-time-credential")).click()
        nextStep()

        val ctType = "CTWalletSamePreAuthorisedInTime"

        val userPin = "5577"
        UserPinHolder.setUserPin(userPin)

        // Enter the did:key
        driver.findElement(By.name("userPinInTime")).sendKeys(userPin)
        log.info { "UserPIN: $userPin" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("preAuthorizedCodeInTime")).sendKeys(ctType)
        log.info { "PreAuthorized Code: $ctType" }
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_in_time"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctType Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_in_time"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctType Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()

    }

    @Test
    fun testCTWalletSamePreAuthorisedDeferred() {

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-deferred-credential")).click()
        nextStep()

        val ctType = "CTWalletSamePreAuthorisedDeferred"

        val userPin = "5577"
        UserPinHolder.setUserPin(userPin)

        // Enter the did:key
        driver.findElement(By.name("userPinDeferred")).sendKeys(userPin)
        log.info { "UserPIN: $userPin" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("preAuthorizedCodeDeferred")).sendKeys(ctType)
        log.info { "PreAuthorized Code: $ctType" }
        nextStep()

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_deferred"
        val initiateResult = awaitCheckboxResult(initiateId, "Initiate")
        log.info { "$ctType Initiate: " + if (initiateResult) "Yes" else "No" }

        initiateResult.shouldBeTrue()

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_deferred"
        val validateResult = awaitCheckboxResult(validateId, "Validate")
        log.info { "$ctType Validate: " + if (validateResult) "Yes" else "No" }

        validateResult.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareIssuerTests(): LoginContext {

        val ctx = userLogin(Max)
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
