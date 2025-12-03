package io.nessus.identity.ebsi

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerConformanceTest : AbstractIssuerConformanceTest() {

    @BeforeAll
    fun setup() {
        startMiniServer()
        startPlaywrightBrowser()
        prepareIssuerTests()
    }

    @AfterAll
    fun tearDown() {
        stopPlaywrightBrowser()
        stopMiniServer()
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
}
