package io.nessus.identity.ebsi

import com.microsoft.playwright.Browser
import com.microsoft.playwright.BrowserContext
import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Page
import com.microsoft.playwright.Playwright
import com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.ktor.server.engine.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.service.AttachmentKeys.DID_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.WALLET_INFO_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext
import io.nessus.identity.waltid.APIException
import io.nessus.identity.waltid.KeyType
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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
            widWalletSvc.login(user.toLoginParams()).also {
                sessions[user.email] = it
            }
        }
        return ctx
    }

    suspend fun loginWithWallet(user: User): LoginContext {
        val ctx = login(user).also {
            val wi = widWalletSvc.listWallets(it).first()
            it.putAttachment(WALLET_INFO_ATTACHMENT_KEY, wi)
        }
        if (ctx.maybeDidInfo == null) {
            widWalletSvc.findDidByPrefix(ctx, "did:key")?.also {
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
                widWalletSvc.registerUser(user.toRegisterUserParams())
                loginWithWallet(user)
            } else {
                throw ex
            }
        }
        if (ctx.maybeDidInfo == null) {
            var didInfo = widWalletSvc.findDidByPrefix(ctx, "did:key")
            if (didInfo == null) {
                val key = widWalletSvc.findKeyByType(ctx, KeyType.SECP256R1)
                    ?: widWalletSvc.createKey(ctx, KeyType.SECP256R1)
                didInfo = widWalletSvc.createDidKey(ctx, "", key.id)
            }
            ctx.putAttachment(DID_INFO_ATTACHMENT_KEY, didInfo)
        }
        return ctx
    }

    fun startNessusServer() {
        embeddedServer = EBSIPortal().createServer()
        embeddedServer.start(wait = false)
    }

    fun stopNessusServer() {
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
    }

    fun stopPlaywrightBrowser() {
        browser.close()
        playwright.close()
    }

    fun authEndpointUri(ctx: LoginContext): String {
        val authUri = "${ConfigProvider.authEndpointUri}/${ctx.targetId}"
        return authUri
    }

    fun walletEndpointUri(ctx: LoginContext): String {
        val walletUri = "${ConfigProvider.walletEndpointUri}/${ctx.targetId}"
        return walletUri
    }

    fun issuerEndpointUri(ctx: LoginContext): String {
        val issuerUri = "${ConfigProvider.issuerEndpointUri}/${ctx.targetId}"
        return issuerUri
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
