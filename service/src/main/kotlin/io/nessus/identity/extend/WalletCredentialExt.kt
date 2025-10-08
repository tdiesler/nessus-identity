package io.nessus.identity.extend

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.VerifiableCredentialV10Jwt

fun WalletCredential.toW3CCredentialJwt(): VerifiableCredentialV10Jwt {
    return VerifiableCredentialV10Jwt.fromEncodedJwt(this.document)
}
