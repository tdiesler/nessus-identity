package io.nessus.identity.service

import com.jayway.jsonpath.Configuration
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.Option
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object CredentialMatcher {

    val log = KotlinLogging.logger {}

    private val jaywayConfig: Configuration = Configuration.defaultConfiguration()
        .addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL)

    // [TODO #238] Add comprehensive Presentation matching
    // https://github.com/tdiesler/nessus-identity/issues/238
    fun matchCredential(wc: WalletCredential, ind: InputDescriptor): Boolean {
        val indId = ind.id
        val fields = ind.constraints?.fields
            ?: throw IllegalStateException("No constraints.fields for: $indId")

        var matchCount = 0
        for (fld in fields) {
            if (fld.path.size != 1) {
                log.warn { "Multiple paths not supported: ${fld.path}" }
                matchCount = 0
                break
            }
            val path = fld.path[0]
            val filterMap = fld.filter?.toMap()
                ?: throw IllegalStateException("No filter in: $fld")

            val vcJwt = SignedJWT.parse(wc.document)
            val pathValue = pathValues(vcJwt, path)

            val containsObj =
                filterMap["contains"] ?: throw IllegalStateException("No filter.contains in: ${fld.filter}")
            val wantedValue = containsObj.jsonObject["const"]?.jsonPrimitive?.content
                ?: throw IllegalStateException("No filter.contains.const in: ${fld.filter}")
            if (pathValue.contains(wantedValue)) {
                matchCount++
            }
        }

        return matchCount == fields.size
    }

    fun pathValues(jwt: SignedJWT, path: String): List<String> {
        val vcPayload = jwt.payload.toString()
        return pathValues(vcPayload, path)
    }

    fun pathValues(json: String, path: String): List<String> {
        val parsed = JsonPath.using(jaywayConfig).parse(json)
        val value = parsed.read<Any?>(path)
        return when (value) {
            is List<*> -> value.mapNotNull { it as? String }
            is String -> listOf(value)
            else -> throw IllegalStateException("Unsupported value type: $value")
        }
    }
}