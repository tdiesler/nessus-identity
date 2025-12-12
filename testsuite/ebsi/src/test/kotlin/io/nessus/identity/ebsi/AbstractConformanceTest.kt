package io.nessus.identity.ebsi

import com.microsoft.playwright.Browser
import com.microsoft.playwright.BrowserContext
import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Page
import com.microsoft.playwright.Playwright
import com.microsoft.playwright.assertions.PlaywrightAssertions
import com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.ktor.server.engine.*
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginContext.Companion.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.LoginContext.Companion.WALLET_INFO_ATTACHMENT_KEY
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.config.FeatureProfile
import io.nessus.identity.config.Features
import io.nessus.identity.config.User
import io.nessus.identity.minisrv.MiniServerBuilder
import io.nessus.identity.toLoginParams
import io.nessus.identity.toRegisterUserParams
import io.nessus.identity.types.KeyType
import io.nessus.identity.types.UserRole
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
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

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    fun login(user: User): LoginContext {
        val ctx = sessions[user.email] ?: runBlocking {
            widWalletService.authLogin(user.toLoginParams())
                .withUserRole(UserRole.Holder)
                .also { sessions[user.email] = it }
        }
        return ctx
    }

    suspend fun loginWithWallet(user: User): LoginContext {
        val ctx = login(user).also {
            val wi = widWalletService.listWallets(it).first()
            it.putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        if (ctx.maybeDidInfo == null) {
            widWalletService.findDidByPrefix(ctx, "did:key")?.also {
                ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, it)
            }
        }
        return ctx
    }

    suspend fun loginWithDid(user: User): LoginContext {
        val ctx = runCatching { loginWithWallet(user) }.getOrElse { ex ->
            val apiEx = ex as? APIException ?: throw ex
            val msg = apiEx.message as String
            if (apiEx.code == 401 && msg.contains("Unknown user")) {
                widWalletService.authRegister(user.toRegisterUserParams())
                loginWithWallet(user)
            } else {
                throw ex
            }
        }
        if (ctx.maybeDidInfo == null) {
            var didInfo = widWalletService.findDidByPrefix(ctx, "did:key")
            if (didInfo == null) {
                val key = widWalletService.findKeyByType(ctx, KeyType.SECP256R1)
                    ?: widWalletService.createKey(ctx, KeyType.SECP256R1)
                didInfo = widWalletService.createDidKey(ctx, "", key.id)
            }
            ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, didInfo)
        }
        return ctx
    }

    fun startMiniServer() {
        Features.setProfile(FeatureProfile.EBSI_V32)
        embeddedServer = MiniServerBuilder().build().create()
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
