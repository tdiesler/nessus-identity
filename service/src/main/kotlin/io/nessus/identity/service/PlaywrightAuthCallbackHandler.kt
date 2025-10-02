package io.nessus.identity.service

import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Playwright
import java.net.URI

class PlaywrightAuthCallbackHandler(val username: String, val password: String) {

    fun getAuthCode(authRequestUrl: URI): String {
        return Playwright.create().use { plw ->
            val browser = plw.firefox().launch(
                BrowserType.LaunchOptions().setHeadless(true)
            )
            val page = browser.newPage()

            // Navigate to Keycloak Authorization Endpoint
            page.navigate("$authRequestUrl")

            // Fill in login form (adjust selectors if your Keycloak theme differs)
            page.locator("#username").fill(username)
            page.locator("#password").fill(password)
            page.locator("#kc-login").click()

            // Wait for the input with id="code"
            page.waitForSelector("#code")

            // Extract the code from the 'value' attribute
            val authCode = page.locator("#code").getAttribute("value")

            browser.close()
            authCode
        }
    }
}