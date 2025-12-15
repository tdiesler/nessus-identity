package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_CREDENTIAL_OFFER_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.service.IssuerService.Companion.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialV11Jwt
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

abstract class AbstractWalletServiceTest: AbstractServiceTest() {

    lateinit var alice: LoginContext

    @BeforeEach
    open fun setUp() {
        runBlocking {
            alice = sessionStore.login(UserRole.Holder, Alice)
        }
    }

    @Test
    open fun getAuthorizationMetadataUrl() {
        runBlocking {
            val metadataUrl = issuerSvc.getAuthorizationMetadataUrl()
            metadataUrl.shouldEndWith("/$WELL_KNOWN_OPENID_CONFIGURATION")
        }
    }

    @Test
    open fun getAuthorizationMetadata() {
        runBlocking {
            val metadata = issuerSvc.getAuthorizationMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    open fun getIssuerMetadataUrl() {
        runBlocking {
            val metadataUrl = issuerSvc.getIssuerMetadataUrl()
            metadataUrl.shouldEndWith("/$WELL_KNOWN_OPENID_CREDENTIAL_ISSUER")
        }
    }

    @Test
    open fun getIssuerMetadata() {
        runBlocking {
            val metadata = issuerSvc.getIssuerMetadata()
            metadata.shouldNotBeNull()
        }
    }

    @Test
    open fun getCredentialAuthorisedInTime() {
        runBlocking {

            val configId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer as CredentialOfferDraft11)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    @Test
    open fun getCredentialAuthorisedDeferred() {
        runBlocking {

            val configId = "CTWalletSameAuthorisedDeferred"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer as CredentialOfferDraft11)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    @Test
    open fun getCredentialPreAuthorisedInTime() {
        runBlocking {

            val configId = "CTWalletSamePreAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, preAuthorized = true, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer as CredentialOfferDraft11)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    @Test
    open fun getCredentialPreAuthorisedDeferred() {
        runBlocking {

            val configId = "CTWalletSamePreAuthorisedDeferred"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, preAuthorized = true, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer as CredentialOfferDraft11)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    suspend fun verifyCredentialOffer(ctx: LoginContext, configId: String, credOffer: CredentialOfferDraft11) {

        val issuerMetadata = issuerSvc.getIssuerMetadata() as IssuerMetadataDraft11
        val credConfig = issuerMetadata.credentialsSupported.first { it.types?.contains(configId) ?: false }
        credConfig.shouldNotBeNull()

        credOffer.credentialIssuer shouldBe issuerMetadata.credentialIssuer
        credOffer.credentials.map { it as CredentialObject }.forEach { co ->
            co.types shouldBe credConfig.types
            co.format shouldBe credConfig.format
        }

        if (configId.contains("PreAuthorised")) {
            val preAuthorizedCode = credOffer.grants?.preAuthorizedCode
            preAuthorizedCode.shouldNotBeNull()
        }

        val authContext = ctx.getAuthContext()
        authContext.putAttachment(EBSI32_CREDENTIAL_OFFER_ATTACHMENT_KEY, credOffer)
        authContext.putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
    }

    fun verifyCredential(ctx: LoginContext, configId: String, credJwt: W3CCredentialV11Jwt) {

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.assertAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY)
        val credConfig = issuerMetadata.credentialsSupported.first { it.types?.contains(configId) ?: false }

        credJwt.types shouldBe credConfig.types

        val subject = credJwt.vc.credentialSubject
        subject.id!! shouldBe ctx.did
        credJwt.sub shouldBe ctx.did
    }
}
