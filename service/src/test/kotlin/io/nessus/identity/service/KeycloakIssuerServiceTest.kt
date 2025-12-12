package io.nessus.identity.backend

import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialV11Jwt
import kotlinx.serialization.json.*

class KeycloakIssuerServiceTest : KeycloakIssuerServiceBase() {

    override val credentialConfigurationId = "oid4vc_natural_person_jwt"

    override suspend fun getCredential(ctx: LoginContext, accessToken: TokenResponse) {

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.getIssuerMetadata()
        val expScopes = authContext.credentialConfigurationIds
            ?.mapNotNull { issuerMetadata.getCredentialScope(it) }
            ?: error { "No scopes from credential configuration ids: ${authContext.credentialConfigurationIds}"}

        val credJwt = walletSvc.getCredential(alice, accessToken) as W3CCredentialV11Jwt
        credJwt.types shouldBeEqual expScopes

        val subject = credJwt.vc.credentialSubject
        subject.claims.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
        subject.id!! shouldBeEqual alice.did
    }
}
