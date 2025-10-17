package io.nessus.identity.service

import com.jayway.jsonpath.JsonPath
import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.CredentialQuery
import io.nessus.identity.types.QueryClaim
import io.nessus.identity.types.VCDataJwt
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

class CredentialMatcherV10 : CredentialMatcher() {

    /**
     * Returns any WalletCredential that matches a given CredentialQuery
     */
    fun matchCredential(cq: CredentialQuery, supplier: Sequence<WalletCredential>): WalletCredential? {

        for (wc in supplier) {

            val vcObj = wc.parsedDocument as JsonObject
            val ctx = JsonPath.parse(vcObj)
            log.debug { "Matching: $vcObj" }

            val vcJwt = VCDataJwt.fromEncoded(wc.document)
            val matchFormat = cq.format == wc.format.value
            val matchTypes = vcJwt.types.any { it in cq.meta.vctValues }
            if (matchFormat && matchTypes) {

                // [TODO #316] Add support for dcql_query.credential.claim_sets matching
                // https://github.com/tdiesler/nessus-identity/issues/316

                val claimsMatched = cq.claims?.all {
                    runCatching {
                        require(it.path.size == 1) { "Invalid path in: $it" }
                        val was = ctx.read<JsonElement>("$.credentialSubject.${it.path[0]}")
                        matchValue(it, was)
                    }.getOrElse {
                        log.error(it) { "Claim match error" }
                        false
                    }
                } ?: true // No claim matching constraints

                if (claimsMatched)
                    return wc
            }
        }

        return null
    }

    private fun matchValue(cond: QueryClaim, was: JsonElement): Boolean {
        val exp = cond.values
        val wasArr = JsonArray(listOf(was))
        val res = exp.isEmpty() || exp == wasArr
        return res
    }
}