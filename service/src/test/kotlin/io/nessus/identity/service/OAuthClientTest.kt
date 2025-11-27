package io.nessus.identity.service

import com.nimbusds.jose.util.Base64URL
import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.TokenRequest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.random.Random

class OAuthClientTest : AbstractServiceTest() {

    lateinit var alice: LoginContext
    lateinit var issuerSvc: IssuerService

    @BeforeEach
    fun setUp() {
        kotlinx.coroutines.runBlocking {
            alice = login(Alice).withDidInfo()
            issuerSvc = IssuerService.createKeycloak()
        }
    }

    @Test
    fun testAuthenticationRequest() {
        val cfg = requireIssuerConfig()
        runBlocking {
            val issMetadata = issuerSvc.getIssuerMetadata()
            val authEndpointUrl = issMetadata.getAuthorizationEndpointUri()

            val rndBytes = Random.nextBytes(32)
            val codeVerifier = Base64URL.encode(rndBytes).toString()

            val authReq = AuthorizationRequestBuilder()
                .withClientId(cfg.clientId)
                .withIssuerMetadata(issMetadata)
                .withRedirectUri("urn:ietf:wg:oauth:2.0:oob")
                .withScopes(listOf("oid4vc_natural_person"))
                .withCodeChallengeMethod("S256")
                .withCodeVerifier(codeVerifier)
                .build()

            val authCode = OAuthClient()
                .withLoginCredentials(Alice.username, Alice.password)
                .sendAuthorizationRequest(authEndpointUrl, authReq)
            authCode.shouldNotBeNull()
        }
    }

    @Test
    fun testTokenRequest() {
        val cfg = requireIssuerConfig()
        runBlocking {
            val issMetadata = issuerSvc.getIssuerMetadata()
            val tokenEndpointUrl = issMetadata.getAuthorizationTokenEndpointUri()
            val tokReq = TokenRequest.ClientCredentials(
                clientId = cfg.serviceId,
                clientSecret = cfg.serviceSecret,
                scopes = listOf("openid"),
            )
            val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
            tokRes.accessToken.shouldNotBeNull()
        }
    }
}
