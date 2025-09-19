package io.nessus.identity.ebsi

import io.kotest.common.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.random.Random

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerConformanceTest : AbstractConformanceTest() {

    // Generates a number between 1000 and 9999
    val userPin = Random.nextInt(1000, 10000)

    @BeforeAll
    fun setup() {
        startNessusServer()
        startPlaywrightBrowser()
        prepareIssuerTests()
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopNessusServer()
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        val ctype = "CTWalletSameAuthorisedInTime"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#in-time-credential")

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_in_time"
        assertCheckboxResult(page, initiateId, "Initiate")

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_in_time"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        val ctype = "CTWalletSameAuthorisedDeferred"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#deferred-credential")

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_deferred"
        assertCheckboxResult(page, initiateId, "Initiate")

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_deferred"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        val ctype = "CTWalletSamePreAuthorisedInTime"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-in-time-credential")

        // Enter the userPin
        page.fill("input[name='userPinInTime']", "$userPin")
        log.info { "Pre-Auth user PIN: $userPin" }

        // Enter the issuerUri
        page.fill("input[name='preAuthorizedCodeInTime']", ctype)
        log.info { "PreAuthorized Code: $ctype" }

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_in_time"
        assertCheckboxResult(page, initiateId, "Initiate")

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_in_time"
        assertCheckboxResult(page, validateId, "Validate")
    }

    @Test
    fun testCTWalletSamePreAuthorisedDeferred() {

        val ctype = "CTWalletSamePreAuthorisedDeferred"
        log.info { ">>>>> Issuer $ctype" }

        // Click the collapsible element
        val page = context.pages().last()
        page.click("#pre-auth-deferred-credential")

        // Enter the userPin
        page.fill("input[name='userPinDeferred']", "$userPin")
        log.info { "Pre-Auth user PIN: $userPin" }

        // Enter the issuerUri
        page.fill("input[name='preAuthorizedCodeDeferred']", ctype)
        log.info { "PreAuthorized Code: $ctype" }

        // Click the "Initiate" link
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_deferred"
        assertCheckboxResult(page, initiateId, "Initiate")

        // Click the "Validate" link
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_deferred"
        assertCheckboxResult(page, validateId, "Validate")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareIssuerTests(): LoginContext {

        val ctx = runBlocking { loginWithDid(Max) }
        ctx.hasDidInfo.shouldBeTrue()

        val page = context.newPage()
        page.navigate("https://hub.ebsi.eu/wallet-conformance/issue-to-holder")

        // Issue Verifiable Credentials to Holder -> Start tests
        page.click("a[href='/wallet-conformance/issue-to-holder/flow']")

        // Enter the did:key
        page.fill("input[name='did']", ctx.did)
        log.info { "DID: ${ctx.did}" }

        // Enter the issuerUri
        page.fill("input[name='clientId']", issuerEndpointUri(ctx))
        log.info { "IssuerUri: ${issuerEndpointUri(ctx)}" }

        // Click "Continue" button
        page.click("xpath=//button[@type='submit'][.//span[text()='Continue']]")

        return ctx
    }
}
