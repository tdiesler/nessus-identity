package io.nessus.identity.utils

import io.ktor.client.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.*

val http = HttpClient {
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
    install(HttpTimeout) {
        requestTimeoutMillis = 120_000   // whole request must finish in 120s
        connectTimeoutMillis = 30_000    // TCP handshake
        socketTimeoutMillis = 120_000    // inactivity between packets
    }
}

fun base64UrlDecode(input: String): ByteArray = Base64.getUrlDecoder().decode(input)

fun base64UrlEncode(input: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(input)

fun urlEncode(input: String): String = URLEncoder.encode(input, "UTF-8")

fun urlDecode(input: String): String = URLDecoder.decode(input, "UTF-8")

fun urlQueryToMap(url: String): Map<String, String> {
    return URI(url).rawQuery?.split("&")?.associate { p ->
        p.split("=", limit = 2).let { (k, v) -> k to urlDecode(v) }
    } ?: mapOf()
}

fun getAuthCodeFromRedirectUrl(redirectUrl: String): String {
    val authCodeUrl = Url(redirectUrl)
    val error = authCodeUrl.parameters["error"]
    if (error != null) {
        val errorMessage = authCodeUrl.parameters["error_description"]
            ?.let { urlDecode(it) }
        error("Authentication Error: $errorMessage")
    }
    val authCode = authCodeUrl.parameters["code"] ?: error("No authorization code")
    return authCode
}

class HttpStatusException(val status: HttpStatusCode, override val message: String) : RuntimeException(message) {
    override fun toString(): String {
        val s = "${javaClass.getName()}[code=$status]"
        return if (message.isNotBlank()) "$s: $message" else s
    }
}

