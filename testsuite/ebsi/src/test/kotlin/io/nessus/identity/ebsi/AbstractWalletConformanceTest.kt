package io.nessus.identity.ebsi

import com.microsoft.playwright.Locator
import com.microsoft.playwright.Page
import io.kotest.common.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.urlEncode
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.waltid.Alice
import java.net.URI

abstract class AbstractWalletConformanceTest : AbstractConformanceTest() {

    fun prepareWalletTests(crossDevive: Boolean): LoginContext {

        val ctx = runBlocking { loginWithDid(Alice) }
        ctx.hasDidInfo.shouldBeTrue()

        val page = context.newPage()
        page.setDefaultTimeout(20_000.0)
        page.setDefaultNavigationTimeout(20_000.0)
        page.navigate("https://hub.ebsi.eu/wallet-conformance")

        // Request and present Verifiable Credentials -> Start tests
        page.click("a[href='/wallet-conformance/holder-wallet']")

        // Holder Wallet Conformance Testing -> Start
        page.click("a[href='/wallet-conformance/holder-wallet/flow?step=0']")

        // Click "Continue" button
        page.click("xpath=//button[.//span[text()='Continue']]")

        // Enter the did:key
        page.fill("input[name='did']", ctx.did)
        log.info { "DID: ${ctx.did}" }

        // Enter the walletUri
        page.fill("input[name='credential_offer_endpoint']", walletEndpointUri(ctx))
        log.info { "WalletUri: ${walletEndpointUri(ctx)}" }

        // Click "Continue" button
        page.click("xpath=//button[@type='submit'][.//span[text()='Continue']]")

        // QR reading capabilities
        if (crossDevive) {
            page.click("xpath=//button[text()='Yes']")
        } else {
            page.click("xpath=//button[text()='No']")
        }

        return ctx
    }

    fun fixupInitiateHref(ctx: LoginContext, link: Locator): Locator {

        val walletUri = walletEndpointUri(ctx)
        var initiateHref = link.getAttribute("href") as String
        log.info { "Initiate href: $initiateHref" }

        val uri = URI(initiateHref)
        val queryParams = urlQueryToMap(initiateHref).toMutableMap()
        val encodedWalletUri = urlEncode(walletUri)

        val credentialOfferEndpoint = queryParams["credential_offer_endpoint"]
        if (credentialOfferEndpoint != encodedWalletUri) {
            queryParams["credential_offer_endpoint"] = encodedWalletUri

            val updatedQuery = queryParams.entries.joinToString("&") { (k, v) -> "$k=$v" }
            initiateHref = "${uri.scheme}://${uri.authority}${uri.path}?$updatedQuery"

            log.info { "Overriding with: $initiateHref" }
        }

        link.evaluate("""(element, newHref) => element.setAttribute("href", newHref)""", initiateHref)
        return link
    }

    fun extractUserPin(page: Page): String {
        val pinElement = page.locator("xpath=//*[contains(text(), 'The required PIN-code will be')]").first()
        val pinElementText = pinElement.textContent() ?: ""
        val pinRegex = Regex("PIN-code will be (\\d{4})")
        val pinMatch = pinRegex.find(pinElementText)
        val userPin = pinMatch?.groupValues?.get(1)
            ?: throw IllegalStateException("PIN not found in: $pinElementText")
        log.info { "Extracted PIN: $userPin" }
        return userPin
    }
}
