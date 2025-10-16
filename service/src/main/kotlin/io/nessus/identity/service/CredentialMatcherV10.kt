package io.nessus.identity.service

import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.ReadContext
import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.QueryClaim
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

class CredentialMatcherV10 : CredentialMatcher() {

    /**
     * Returns true if the credential matches all DCQL assertions.
     */
    fun matchCredential(wc: WalletCredential, dcql: DCQLQuery): Boolean {
        val vcObj = wc.parsedDocument as JsonObject
        val ctx: ReadContext = JsonPath.parse(vcObj)
        log.debug { "Matching: $vcObj" }
        val matched = dcql.credentials.firstOrNull { qc ->
            qc.claims ?: error("No claims")
            qc.claims.all {
                try {
                    if (it.path.size != 1) error("Invalid path in: $it")
                    val was = ctx.read<JsonElement>("$.credentialSubject." + it.path[0])
                    matchValue(it, was)
                } catch (ex: Exception) {
                    log.error { ex }
                    false
                }
            }
        }
        return matched != null
    }

    private fun matchValue(cond: QueryClaim, was: JsonElement): Boolean {
        val exp = cond.values
        val wasArr = JsonArray(listOf(was))
        val res = exp.isEmpty() || exp == wasArr
        return res
    }
}