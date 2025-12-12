package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import org.junit.jupiter.api.Test
import kotlin.test.Ignore

abstract class AbstractIssuerServiceTest: AbstractServiceTest() {

    @Test
    fun getIssuerMetadata() {
        runBlocking {
            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER")
            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    fun getCredentialAuthorisedInTime() {
        runBlocking {
            val credConfigId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId)
            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, credJwt)
        }
    }

    @Test
    @Ignore
    fun getCredentialAuthorisedDeferred() {
        // [TODO] getCredentialAuthorisedDeferred
    }

    @Test
    fun getCredentialPreAuthorisedInTime() {
        runBlocking {
            val credConfigId = "CTWalletSamePreAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(credConfigId, preAuthorized = true, targetUser = Alice)
            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, credJwt)
        }
    }

    @Test
    @Ignore
    fun getCredentialPreAuthorisedDeferred() {
        // [TODO] getCredentialPreAuthorisedDeferred
    }

    private suspend fun verifyCredential(ctx: LoginContext, credJwt: W3CCredentialJwt) {

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.getIssuerMetadata()
        val expScopes = authContext.credentialConfigurationIds
            ?.mapNotNull { issuerMetadata.getCredentialScope(it) }
            ?: error { "No scopes from credential configuration ids: ${authContext.credentialConfigurationIds}"}

        credJwt as W3CCredentialV11Jwt
        credJwt.types shouldBeEqual expScopes

        val subject = credJwt.vc.credentialSubject
        subject.id!! shouldBeEqual alice.did
    }
}
