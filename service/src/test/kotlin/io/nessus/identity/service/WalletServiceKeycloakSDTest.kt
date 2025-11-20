package io.nessus.identity.service

import io.kotest.matchers.equals.shouldBeEqual
import io.nessus.identity.types.TokenResponseV0
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.waltid.Alice

class WalletServiceKeycloakSDTest : WalletServiceKeycloakBase() {

    override val credentialConfigurationId = "oid4vc_natural_person"

    override suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponseV0) {

        val issuerMetadata = authContext.getIssuerMetadata()
        val expScopes = authContext.credentialConfigurationIds
            ?.mapNotNull { issuerMetadata.credentialConfigurationsSupported[it]?.scope }
            ?: error { "No scopes from credential configuration ids: ${authContext.credentialConfigurationIds}"}

        val vcJwt = walletSvc.getCredential(authContext, accessToken) as VCDataSdV11Jwt
        vcJwt.types shouldBeEqual expScopes

        vcJwt.disclosedValue("sub") shouldBeEqual alice.did
        vcJwt.disclosedValue("email") shouldBeEqual Alice.email
    }
}
