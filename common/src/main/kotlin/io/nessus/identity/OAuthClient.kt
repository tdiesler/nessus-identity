package io.nessus.identity

import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Playwright
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.utils.http
import kotlinx.serialization.json.*

class OAuthClient {

    lateinit var loginCredentials: LoginCredentials

    fun withLoginCredentials(username: String, password: String): OAuthClient {
        this.loginCredentials = LoginCredentials(username, password)
        return this
    }

    fun sendAuthorizationRequest(endpointUrl: String, authReq: AuthorizationRequestV0): String {
        val authParams = authReq.toRequestParameters()
        log.info { "AuthorizationParams: $authParams" }
        val authCode = Playwright.create().use { plw ->
            val browser = plw.firefox().launch(
                BrowserType.LaunchOptions().setHeadless(true)
            )
            val page = browser.newPage()

            // Navigate to Keycloak Authorization Endpoint
            val authRequestUrl = authReq.toRequestUrl(endpointUrl)
            page.navigate(authRequestUrl)

            // Fill in login form (adjust selectors if your Keycloak theme differs)
            page.locator("#username").fill(loginCredentials.username)
            page.locator("#password").fill(loginCredentials.password)
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

    suspend fun sendTokenRequest(endpointUrl: String, tokenRequest: TokenRequest): TokenResponse {
        val authParams = tokenRequest.getParameters()
        log.info { "Send TokenRequest: $endpointUrl" }
        val res = http.post(endpointUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(Parameters.Companion.build {
                authParams.forEach { (k, vals) -> log.info { "  $k=$vals" }}
                authParams.forEach { (k, vals) -> append(k, vals.first()) }
            }.formUrlEncode())
        }
        val authRes = handleApiResponse(res) as TokenResponse
        return authRes
    }

    companion object {
        val log = KotlinLogging.logger {}
        @Suppress("UNCHECKED_CAST")
        suspend inline fun <reified T> handleApiResponse(res: HttpResponse): T {

            if (res.status.value in 200..<300) {
                if (!isBinary(getContentType(res))) {
                    val body = res.bodyAsText()
                    log.debug { "OAuth Response: $body" }
                }
                val resVal = when (T::class) {
                    ByteArray::class -> res.body() as T
                    Boolean::class -> {
                        val body = res.bodyAsText()
                        (body.ifEmpty { "false" }.toBoolean()) as T                    }
                    HttpResponse::class -> res as T
                    String::class -> res.bodyAsText() as T
                    else -> {
                        val json = Json { ignoreUnknownKeys = true }
                        json.decodeFromString<T>(res.bodyAsText())
                    }
                }
                return resVal
            }
            error("APIError[code=${res.status.value}, message=${res.bodyAsText()}]")
        }

        fun getContentType(res: HttpResponse): ContentType? {
            return res.headers[HttpHeaders.ContentType]?.let { ContentType.Companion.parse(it) }
        }

        fun isBinary(contentType: ContentType?): Boolean {
            val txtSubtypes = listOf("json", "xml", "javascript", "x-www-form-urlencoded")
            if (contentType == null) return false
            return when (contentType.contentType) {
                "image", "audio", "video" -> true
                "application" -> contentType.contentSubtype !in txtSubtypes
                else -> false
            }
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun redactedParams(params: Map<String, List<String>>): Map<String, List<String>> {
        val keys = listOf("client_secret", "password")
        return params.mapValues { (k, v) ->
            if (k in keys) listOf("******") else v
        }
    }
}