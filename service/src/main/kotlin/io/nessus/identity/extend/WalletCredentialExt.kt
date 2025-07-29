package io.nessus.identity.extend

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.W3CCredentialJwt

fun WalletCredential.toW3CCredentialJwt(): W3CCredentialJwt {
    return W3CCredentialJwt.fromEncodedJwt(this.document)
}
