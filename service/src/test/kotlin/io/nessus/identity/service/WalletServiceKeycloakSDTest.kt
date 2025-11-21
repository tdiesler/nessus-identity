package io.nessus.identity.service

import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.waltid.Alice

class WalletServiceKeycloakSDTest : WalletServiceKeycloakBase() {

    override val credentialConfigurationId = "oid4vc_natural_person"

    override suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponse) {

        val issuerMetadata = authContext.getIssuerMetadata()
        val expScopes = authContext.credentialConfigurationIds
            ?.mapNotNull { issuerMetadata.getCredentialScope(it) }
            ?: error { "No scopes from credential configuration ids: ${authContext.credentialConfigurationIds}"}

        val credJwt = walletSvc.getCredential(authContext, accessToken) as W3CCredentialSdV11Jwt
        credJwt.types shouldBeEqual expScopes

        credJwt.disclosedValue("sub") shouldBeEqual alice.did
        credJwt.disclosedValue("email") shouldBeEqual Alice.email
    }
}
