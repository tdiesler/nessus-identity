package io.nessus.identity.ebsi

import io.kotest.common.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Alice

abstract class AbstractVerifierConformanceTest : AbstractConformanceTest() {

    fun prepareVerifierTests(): LoginContext {

        val ctx = runBlocking { loginWithDid(Alice) }
        ctx.hasDidInfo.shouldBeTrue()

        val page = context.newPage()
        page.setDefaultTimeout(20_000.0)
        page.setDefaultNavigationTimeout(20_000.0)
        page.navigate("https://hub.ebsi.eu/wallet-conformance/verifier")

        // Verifier Conformance Testing -> Start
        page.click("a[href='/wallet-conformance/verifier/flow']")

        // Enter the authUri
        page.fill("input[name='clientId']", authEndpointUri(ctx))
        log.info { "AuthUri: ${authEndpointUri(ctx)}" }

        // Click "Continue" button
        page.click("xpath=//button[@type='submit'][.//span[text()='Continue']]")

        // Click the collapsible element
        page.click("#id-token-exchange")

        // Click the collapsible element
        page.click("#verifiable-presentations")

        return ctx
    }
}

