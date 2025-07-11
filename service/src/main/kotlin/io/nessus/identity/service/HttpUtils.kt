package io.nessus.identity.service

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URLDecoder
import kotlin.collections.associate
import kotlin.let
import kotlin.text.split
import kotlin.to

val http = HttpClient {
    install(ContentNegotiation) {
        json()
    }
}

fun urlQueryToMap(url: String): Map<String, String> {
    return URI(url).rawQuery?.split("&")?.associate { p ->
        p.split("=", limit = 2).let { (k, v) -> k to URLDecoder.decode(v, "UTF-8") }
    } ?: mapOf()
}

@Serializable
data class CookieData(val wid: String, var did: String? = null) {
    companion object {
        const val NAME = "CookieData"
    }
}

class HttpStatusException(val status: HttpStatusCode, override val message: String) : RuntimeException(message) {
    override fun toString(): String {
        val s = "${javaClass.getName()}[code=$status]"
        return if (message.isNotBlank()) "$s: $message" else s
    }
}

