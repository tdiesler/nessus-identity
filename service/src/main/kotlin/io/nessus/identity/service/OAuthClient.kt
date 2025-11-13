package io.nessus.identity.service

import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Playwright
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponseV0
import kotlinx.serialization.json.*

class OAuthClient {

    lateinit var loginPage: LoginPage

    fun withLoginCredentials(username: String, password: String): OAuthClient {
        this.loginPage = LoginPage(username, password)
        return this
    }

    fun sendAuthorizationRequest(endpointUrl: String, authReq: AuthorizationRequest): String {
        val authParams = authReq.getParameters()
        log.info { "AuthorizationParams: $authParams" }
        val authCode = Playwright.create().use { plw ->
            val browser = plw.firefox().launch(
                BrowserType.LaunchOptions().setHeadless(true)
            )
            val page = browser.newPage()

            // Navigate to Keycloak Authorization Endpoint
            val authRequestUrl = authReq.getAuthorizationRequestUrl(endpointUrl)
            page.navigate(authRequestUrl)

            // Fill in login form (adjust selectors if your Keycloak theme differs)
            page.locator("#username").fill(loginPage.username)
            page.locator("#password").fill(loginPage.password)
            page.locator("#kc-login").click()

            // Wait for the input with id="code"
            page.waitForSelector("#code")

            // Extract the code from the 'value' attribute
            val authCode = page.locator("#code").getAttribute("value")

            browser.close()
            authCode
        }
        return authCode
    }

    suspend fun sendTokenRequest(endpointUrl: String, tokReq: TokenRequest): TokenResponseV0 {
        val authParams = tokReq.getParameters()
        log.info { "AuthorizationUrl: $endpointUrl" }
        log.info { "AuthorizationParams: ${redactedParams(authParams)}" }
        val res = http.post(endpointUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(Parameters.build {
                tokReq.getParameters().forEach { (k, vals) ->
                    vals.forEach { v -> append(k, v) }
                }
            }.formUrlEncode())
        }
        val authRes = handleApiResponse(res) as TokenResponseV0
        return authRes
    }

    companion object {
        val log = KotlinLogging.logger {}
        @Suppress("UNCHECKED_CAST")
        suspend inline fun <reified T> handleApiResponse(res: HttpResponse): T {
            val body = res.bodyAsText()
            if (res.status.value in 200..<300) {
                log.info { "Response: $body" }
                val resVal = if (T::class == HttpResponse::class) {
                    res as T
                } else if (T::class == String::class) {
                    body as T
                } else if (T::class == Boolean::class) {
                    when {
                        body.isEmpty() -> true as T
                        else -> body.toBoolean() as T
                    }
                } else {
                    val json = Json { ignoreUnknownKeys = true }
                    json.decodeFromString<T>(body)
                }
                return resVal
            }
            error("APIError[code=${res.status.value}, message=$body]")
        }
    }

    data class LoginPage(
        val username: String,
        val password: String
    )

    // Private ---------------------------------------------------------------------------------------------------------

    private fun redactedParams(params: Map<String, List<String>>): Map<String, List<String>> {
        val keys = listOf("client_secret", "password")
        return params.mapValues { (k, v) ->
            if (k in keys) listOf("******") else v
        }
    }
}