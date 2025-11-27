package io.nessus.identity.ebsi

import io.kotest.common.runBlocking
import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.Max
import kotlin.random.Random

abstract class AbstractIssuerConformanceTest : AbstractConformanceTest() {

    // Generates a number between 1000 and 9999
    val userPin = Random.nextInt(1000, 10000)

    fun prepareIssuerTests(): LoginContext {

        val ctx = runBlocking { loginWithDid(Max) }
        ctx.hasDidInfo.shouldBeTrue()

        val page = context.newPage()
        page.setDefaultTimeout(20_000.0)
        page.setDefaultNavigationTimeout(20_000.0)
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
