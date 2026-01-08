package io.nessus.identity.minisrv

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.AuthorizationContext.Companion.CREDENTIAL_OFFER_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginCredentials
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.config.User
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialV11Jwt
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

abstract class AbstractWalletServiceTest : AbstractServiceTest() {

    lateinit var alice: LoginContext

    @BeforeEach
    open fun setUp() {
        runBlocking {
            alice = sessionStore.login(UserRole.Holder, Alice)
        }
    }

    open fun getLoginCredentials(user: User): LoginCredentials? = null

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
    fun authorizeWithIDTokenFlow() {
        runBlocking {
            val configId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val authCode = walletSvc.authorizeWithIDTokenFlow(alice, credOffer)
            val tokenResponse = walletSvc.getAccessTokenFromCode(alice, authCode)
            verifyTokenResponse(alice, configId, tokenResponse)
        }
    }

    @Test
    fun authorizeWithCredentialOffer() {
        runBlocking {
            val configId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val clientId = walletSvc.defaultClientId
            val loginCredentials = getLoginCredentials(Alice)
            val tokenResponse = walletSvc.authorizeWithCredentialOffer(alice, clientId, credOffer, loginCredentials)
            verifyTokenResponse(alice, configId, tokenResponse)
        }
    }

    @Test
    fun authorizeWithCredentialOfferPreAuthorized() {
        runBlocking {
            val configId = "CTWalletSamePreAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, preAuthorized = true, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val clientId = walletSvc.defaultClientId
            val tokenResponse = walletSvc.authorizeWithCredentialOffer(alice, clientId, credOffer)
            verifyTokenResponse(alice, configId, tokenResponse)
        }
    }

    @Test
    open fun getCredentialAuthorisedInTime() {
        runBlocking {
            val configId = "CTWalletSameAuthorisedInTime"
            val credOffer = issuerSvc.createCredentialOffer(configId, alice.did, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val loginCredentials = getLoginCredentials(Alice)
            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer, loginCredentials)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    @Test
    open fun getCredentialPreAuthorisedInTime() {
        runBlocking {

            val configId = "CTWalletSamePreAuthorisedInTime"
            val credOffer =
                issuerSvc.createCredentialOffer(configId, alice.did, preAuthorized = true, targetUser = Alice)
            verifyCredentialOffer(alice, configId, credOffer)

            val credJwt = walletSvc.getCredentialFromOffer(alice, credOffer)
            verifyCredential(alice, configId, credJwt as W3CCredentialV11Jwt)
        }
    }

    suspend fun verifyCredentialOffer(ctx: LoginContext, configId: String, credOffer: CredentialOffer) {

        val authContext = ctx.getAuthContext().withCredentialOffer(credOffer)
        val issuerMetadata = authContext.resolveIssuerMetadata()
        credOffer.credentialIssuer shouldBe issuerMetadata.credentialIssuer

        when (credOffer) {
            is CredentialOfferV0 -> {
                issuerMetadata as IssuerMetadataV0
                val credConfig = issuerMetadata.credentialConfigurationsSupported[configId]
                credConfig.shouldNotBeNull()
            }
            is CredentialOfferDraft11 -> {
                issuerMetadata as IssuerMetadataDraft11
                val credConfig = issuerMetadata.credentialsSupported.first { it.types?.contains(configId) ?: false }
                credOffer.credentials.map { it as CredentialObject }.forEach { co ->
                    co.types shouldBe credConfig.types
                    co.format shouldBe credConfig.format

                }
            }
        }
        if (configId.contains("PreAuthorised")) {
            val preAuthorizedCode = credOffer.grants?.preAuthorizedCode
            preAuthorizedCode.shouldNotBeNull()
        }

        authContext.putAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY, credOffer)
        authContext.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
    }

    suspend fun verifyCredential(ctx: LoginContext, configId: String, credJwt: W3CCredentialV11Jwt) {

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.assertIssuerMetadata()

        when (issuerMetadata) {
            is IssuerMetadataV0 -> {
                credJwt.types shouldBe listOf(configId)
                val credConfig = issuerMetadata.credentialConfigurationsSupported[configId]
                credConfig.shouldNotBeNull()
            }

            is IssuerMetadataDraft11 -> {
                val credConfig = issuerMetadata.credentialsSupported.first { it.types?.contains(configId) ?: false }
                credJwt.types shouldBe credConfig.types
            }
        }

        val subject = credJwt.vc.credentialSubject
        subject.id!! shouldBe ctx.did
        credJwt.sub shouldBe ctx.did
    }

    fun verifyTokenResponse(ctx: LoginContext, configId: String, tokenResponse: TokenResponse) {
        val accessToken = tokenResponse.accessToken
        accessToken.shouldNotBeNull()
    }
}
