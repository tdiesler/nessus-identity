package io.nessus.identity.extend

import id.walt.oid4vc.data.CredentialOffer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

fun CredentialOffer.getTypes(): List<String> {
    val ctypes = mutableListOf<String>()
    when (this) {
        is CredentialOffer.Draft11 ->
            this.credentials
                .map { it.jsonObject }
                .map { it.getValue("types").jsonArray }
                .map { it.jsonPrimitive.content }
        else ->
            throw IllegalStateException("Unsupported CredentialOffer: ${Json.encodeToString(this)}")
    }
    return ctypes
}
