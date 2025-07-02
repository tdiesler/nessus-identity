package io.nessus.identity.portal

import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import java.net.URI
import java.net.URLDecoder

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
