package io.nessus.identity.service

import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.Alice
import kotlinx.serialization.json.*

class WalletServiceKeycloakTest : WalletServiceKeycloakBase() {

    override val credentialConfigurationId = "oid4vc_identity_credential"

    override suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponse) {

        val issuerMetadata = authContext.getIssuerMetadata()
        val expScopes = authContext.credentialConfigurationIds
            ?.mapNotNull { issuerMetadata.getCredentialScope(it) }
            ?: error { "No scopes from credential configuration ids: ${authContext.credentialConfigurationIds}"}

        val credJwt = walletSvc.getCredential(authContext, accessToken) as W3CCredentialV11Jwt
        credJwt.types shouldBeEqual expScopes

        val subject = credJwt.vc.credentialSubject
        subject.claims.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
        subject.id!! shouldBeEqual alice.did
    }
}
