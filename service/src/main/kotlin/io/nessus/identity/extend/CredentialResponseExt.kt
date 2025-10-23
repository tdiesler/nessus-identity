package io.nessus.identity.extend

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.responses.CredentialResponse
import kotlinx.serialization.json.*

fun CredentialResponse.toSignedJWT(): SignedJWT {
    if (format == CredentialFormat.jwt_vc) {
        val content = (credential as JsonPrimitive).content
        return SignedJWT.parse(content)
    }
    throw IllegalStateException("Credential format unsupported: $format")
}


