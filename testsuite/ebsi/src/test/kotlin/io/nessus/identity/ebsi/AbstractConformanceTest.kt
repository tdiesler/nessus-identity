package io.nessus.identity.ebsi

import com.microsoft.playwright.Browser
import com.microsoft.playwright.BrowserContext
import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Page
import com.microsoft.playwright.Playwright
import com.microsoft.playwright.assertions.PlaywrightAssertions
import com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.server.engine.*
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.FeatureProfile
import io.nessus.identity.config.Features
import io.nessus.identity.minisrv.BasicSessionStore
import io.nessus.identity.minisrv.MiniServerBuilder
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.WalletService
import kotlinx.serialization.json.*
import org.junit.jupiter.api.TestInstance

/**
 * brew install --cask google-chrome
 * brew install chromedriver
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
open class AbstractConformanceTest {

    val log = KotlinLogging.logger {}

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var playwright: Playwright
    lateinit var browser: Browser
    lateinit var context: BrowserContext

    val sessionStore = BasicSessionStore()

    fun startMiniServer() {
        Features.setProfile(FeatureProfile.EBSI_V32)
        embeddedServer = MiniServerBuilder()
            .withIssuerService(IssuerService.createNative())
            .withWalletService(WalletService.createNative())
            .withVerifierService(VerifierService.createNative())
            .withSessionsStore(sessionStore)
            .build().create()
        embeddedServer.start(wait = false)
    }

    fun stopMiniServer() {
        embeddedServer.stop(3000, 5000)
    }

    fun startPlaywrightBrowser() {
        playwright = Playwright.create()

        // Launch Chromium
        browser = playwright.chromium().launch(
            BrowserType.LaunchOptions().setHeadless(true)
        )

        val screenSize = java.awt.Toolkit.getDefaultToolkit().screenSize
        val screenWidth = screenSize.width
        val screenHeight = screenSize.height

        context = browser.newContext(Browser.NewContextOptions()
            .setViewportSize(screenWidth / 2, (screenHeight * 0.8).toInt()))

        PlaywrightAssertions.setDefaultAssertionTimeout(20_000.0)
    }

    fun stopPlaywrightBrowser() {
        browser.close()
        playwright.close()
    }

    fun issuerEndpointUri(ctx: LoginContext): String {
        val config = ConfigProvider.requireIssuerConfig("proxy")
        val issuerUri = "${config.baseUrl}/${ctx.targetId}"
        return issuerUri
    }
    fun walletEndpointUri(ctx: LoginContext): String {
        val config = ConfigProvider.requireWalletConfig("proxy")
        val walletUri = "${config.baseUrl}/${ctx.targetId}"
        return walletUri
    }

    fun verifierEndpointUri(ctx: LoginContext): String {
        val config = ConfigProvider.requireVerifierConfig("proxy")
        val authUri = "${config.baseUrl}/${ctx.targetId}"
        return authUri
    }

    fun assertCheckboxResult(page: Page, checkboxId: String, buttonText: String) {

        page.locator("#$checkboxId ~ button:has-text(\"$buttonText\")").click()

        val label = page.locator("#$checkboxId ~ label[for='$checkboxId'] span:first-child")
        assertThat(label).hasText("Yes")
    }

    fun verifyCredential(ctype: String, credJson: String) {
        val jsonObj = Json.decodeFromString<JsonObject>(credJson)
        val vcObj = jsonObj.getValue("vc").jsonObject
        val types = vcObj.getValue("type").jsonArray.map { it.jsonPrimitive.content }
        if (!types.contains(ctype)) throw IllegalStateException("VC types $types do not contain: $ctype")
    }
}
