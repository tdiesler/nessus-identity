package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.webwallet.db.models.WalletCredential
import kotlinx.serialization.json.*

class CredentialMatcherDraft11 : CredentialMatcher() {

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

            val credJwt = SignedJWT.parse(wc.document)
            val pathValue = pathValues(credJwt, path)

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
}