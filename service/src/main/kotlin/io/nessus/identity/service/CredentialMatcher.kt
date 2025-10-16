package io.nessus.identity.service

import com.jayway.jsonpath.Configuration
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.Option
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging

abstract class CredentialMatcher {

    companion object {

        val log = KotlinLogging.logger {}

        val jaywayConfig: Configuration = Configuration.defaultConfiguration()
            .addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL)

        fun pathValues(jwt: SignedJWT, path: String): List<String> {
            val vcPayload = jwt.payload.toString()
            return pathValues(vcPayload, path)
        }

        fun pathValues(json: String, path: String): List<String> {
            val parsed = JsonPath.using(jaywayConfig).parse(json)
            return try {
                when (val value = parsed.read<Any?>(path)) {
                    is List<*> -> value.mapNotNull { it as? String }
                    is String -> listOf(value)
                    null -> emptyList()
                    else -> throw IllegalStateException("Unsupported value type: $value")
                }
            } catch (ex: Exception) {
                log.error { ex }
                emptyList()
            }
        }
    }
}