package io.nessus.identity.backend

import com.nimbusds.jwt.SignedJWT
import io.kotest.common.runBlocking
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.service.AbstractServiceTest
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.NativeIssuerService
import io.nessus.identity.service.NativeWalletService
import io.nessus.identity.service.WalletService
import org.junit.jupiter.api.Test

class NativeIssuerServiceTest : AbstractServiceTest() {

    val issuerSvc = IssuerService.createNative() as NativeIssuerService
    val walletSvc = WalletService.createNative() as NativeWalletService

    @Test
    fun getCredentialInTime() {

        // Issue Verifiable Credentials - In-time Issuance
        // https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance

        // Issuer creates a CredentialOffer
        // Holder receives the CredentialOffer
        //
        // Holder creates AuthorizationRequest
        //
        // Issuer receives AuthorizationRequest
        //  - Issuer creates IDToken AuthorizationRequest (response_type=id_token, response_mode=direct_post)
        //  - Holder receives IDToken AuthorizationRequest
        //  - Holder responds with the requested IDToken
        // Issuer sends AuthorizationResponse (code)
        //
        // Holder sends TokenRequest
        // Issuer sends TokenResponse
        //
        // Holder sends CredentialRequest
        // Issuer sends CredentialResponse

        runBlocking {
            val alice = LoginContext.login(Alice).withDidInfo()

            val authMetadata = issuerSvc.getAuthorizationMetadata()
            val issuerMetadata = issuerSvc.getIssuerMetadata()
                .withAuthorizationMetadata(authMetadata)

            // Issuer creates a CredentialOffer
            //
            val credOffer = issuerSvc.createCredentialOffer("CTWalletSameAuthorisedInTime")

            // Holder creates AuthorizationRequest
            //
            alice.getAuthContext().withIssuerMetadata(issuerMetadata)
            val authRequest = walletSvc.buildAuthorizationRequestFromOffer(alice, credOffer)

            // Issuer receives AuthorizationRequest and creates a IDToken AuthorizationRequest
            //
            val idTokenRequest = issuerSvc.createIDTokenRequest(authRequest)

            val idTokenJwt = walletSvc.createIDToken(alice, idTokenRequest)

            val authCode = issuerSvc.getAuthCodeFromIDToken(idTokenJwt)

            val tokenRequest = walletSvc.getTokenRequestFromAuthorizationCode(alice, authCode)

            val tokenResponse = issuerSvc.getTokenResponse(tokenRequest)

            val credRequest = walletSvc.buildCredentialRequest(alice, authRequest)

            val accessTokenJwt = SignedJWT.parse(tokenResponse.accessToken)
            issuerSvc.getCredentialFromRequest(credRequest, accessTokenJwt)
        }
    }
}
