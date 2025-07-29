package io.nessus.identity.extend

import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantDetails
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

fun CredentialOffer.getCredentialTypes(): List<String> {
    val ctypes = mutableListOf<String>()
    when (this) {

        is CredentialOffer.Draft11 ->
            this.credentials
                .map { it.jsonObject }
                .map { it.getValue("types") }
                .map { it as JsonArray }
                .first {
                    val values = it.map { el -> el.jsonPrimitive.content }
                    ctypes.addAll(values)
                }

        else ->
            throw IllegalStateException("Unsupported CredentialOffer: ${Json.encodeToString(this)}")
    }
    return ctypes
}

fun CredentialOffer.getPreAuthorizedGrantDetails(): GrantDetails? {
    return this.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
}

fun CredentialOffer.isPreAuthorized(): Boolean {
    return this.grants.containsKey("urn:ietf:params:oauth:grant-type:pre-authorized_code")
}
