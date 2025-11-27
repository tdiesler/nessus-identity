package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.types.TokenResponse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

abstract class WalletServiceKeycloakBaseTest : AbstractServiceTest() {

    lateinit var alice: LoginContext

    lateinit var issuerSvc: IssuerService
    lateinit var walletSvc: WalletService

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            issuerSvc = IssuerService.createKeycloak()

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = login(Alice).withDidInfo()
            walletSvc = WalletService.create()
        }
    }

    abstract val credentialConfigurationId: String

    abstract suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponse)

    @Test
    fun getCredentialWithoutOffer() {
        runBlocking {
            val configId = credentialConfigurationId

            val authContext = AuthorizationContext.create(alice)
                .withIssuerMetadata(issuerSvc.getIssuerMetadata())
                .withCredentialConfigurationId(configId)

            val authCode = walletSvc.getAuthorizationCode(
                authContext,
                username = Alice.username,
                password = Alice.password
            )
            val accessToken = walletSvc.getAccessTokenFromAuthorizationCode(authContext, authCode)

            getCredential(authContext, accessToken)
        }
    }

    @Test
    fun getCredentialFromOfferInTime() {
        runBlocking {
            val configId = credentialConfigurationId

            val offerUri = issuerSvc.createCredentialOfferUri(configId)
            val credOffer = walletSvc.getCredentialOffer(offerUri)
            val authContext = AuthorizationContext.create(alice).withCredentialOffer(credOffer)
            val authCode = walletSvc.getAuthorizationCode(
                authContext,
                username = Alice.username,
                password = Alice.password
            )
            val accessToken = walletSvc.getAccessTokenFromAuthorizationCode(authContext, authCode)

            getCredential(authContext, accessToken)
        }
    }

    @Test
    fun getCredentialFromOfferPreAuthorized() {
        runBlocking {
            val configId = credentialConfigurationId

            val offerUri = issuerSvc.createCredentialOfferUri(configId, true, Alice)
            val credOffer = walletSvc.getCredentialOffer(offerUri)

            val authContext = AuthorizationContext.create(alice)
            val accessToken = walletSvc.getAccessTokenFromCredentialOffer(authContext, credOffer)

            getCredential(authContext, accessToken)
        }
    }
}
