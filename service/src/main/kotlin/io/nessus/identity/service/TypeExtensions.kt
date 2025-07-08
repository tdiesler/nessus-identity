package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.responses.CredentialResponse
import kotlinx.serialization.json.JsonPrimitive

fun CredentialOffer.getPreAuthorizedGrantDetails(): GrantDetails? {
    return this.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
}

fun CredentialResponse.toSignedJWT(): SignedJWT {
    if (this.format == CredentialFormat.jwt_vc) {
        val content = (this.credential as JsonPrimitive).content
        return SignedJWT.parse(content)
    }
    throw IllegalStateException("Credential format unsupported: ${this.format}")
}


