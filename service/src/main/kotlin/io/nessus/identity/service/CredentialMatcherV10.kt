package io.nessus.identity.service

import com.jayway.jsonpath.JsonPath
import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.CredentialQuery
import io.nessus.identity.types.QueryClaim
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import kotlinx.serialization.json.*

class CredentialMatcherV10 : CredentialMatcher() {

    /**
     * Returns any WalletCredential that matches a given CredentialQuery
     */
    fun matchCredential(cq: CredentialQuery, supplier: Sequence<WalletCredential>): Pair<WalletCredential, List<QueryClaim>?>? {

        for (wc in supplier) {

            val vcObj = wc.parsedDocument as JsonObject
            val ctx = JsonPath.parse(vcObj)

            val credJwt = W3CCredentialJwt.fromEncoded(wc.document)
            val matchFormat = cq.format == wc.format.value
            val matchTypes = credJwt.types.any { it in cq.meta.vctValues }
            if (matchFormat && matchTypes) {

                // [TODO #316] Add support for dcql_query.credential.claim_sets matching
                // https://github.com/tdiesler/nessus-identity/issues/316

                val claimsMatched = cq.claims?.all { cl ->
                    require(cl.path.size == 1) { "Invalid path in: $cl" }
                    val claimName = cl.path[0]
                    val was: JsonElement? = when (credJwt) {

                        is W3CCredentialSdV11Jwt -> credJwt.disclosures
                            .find {
                                it.claim == claimName
                            }?.let { JsonPrimitive(it.value) }

                        else ->
                            runCatching {
                                ctx.read<JsonElement>("$.credentialSubject.$claimName")
                            }.getOrElse { ex ->
                                log.error(ex) { "Error processing: $vcObj" }
                                null
                            }
                    }

                    was?.let { matchValue(cl, was) } ?: false

                } ?: true // No claim matching constraints

                if (claimsMatched)
                    return Pair(wc, cq.claims)
            }
        }

        return null
    }

    private fun matchValue(cond: QueryClaim, was: JsonElement): Boolean {
        val exp = cond.values
        val wasArr = JsonArray(listOf(was))
        return exp.isEmpty() || exp == wasArr
    }
}