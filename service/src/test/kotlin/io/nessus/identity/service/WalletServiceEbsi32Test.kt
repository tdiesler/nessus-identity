package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.kotest.common.runBlocking
import io.nessus.identity.config.ConfigProvider.Alice
import io.nessus.identity.config.ConfigProvider.Max
import org.junit.jupiter.api.Test

class WalletServiceEbsi32Test : AbstractServiceTest() {

    val walletSvc = WalletService.create()
    val issuerSvc = IssuerService.createEbsi()

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
            val holder = LoginContext.login(Alice).withDidInfo()
            val issuer = LoginContext.login(Max).withDidInfo()

            val authMetadata = issuerSvc.getAuthorizationMetadata()
            val issuerMetadata = issuerSvc.getIssuerMetadata()
                .withAuthorizationMetadata(authMetadata)

            // Issuer creates a CredentialOffer
            //
            val credOffer = issuerSvc.createCredentialOffer("CTWalletSameAuthorisedInTime")

            // Holder creates AuthorizationRequest
            //
            holder.getAuthContext().withIssuerMetadata(issuerMetadata)
            val authRequest = walletSvc.buildAuthorizationRequestFromOffer(holder, credOffer)

            // Issuer receives AuthorizationRequest and creates a IDToken AuthorizationRequest
            //
            val idTokenRequest = issuerSvc.createIDTokenRequest(issuer, authRequest)

            val idTokenJwt = walletSvc.createIDToken(holder, idTokenRequest)

            val authCode = issuerSvc.getAuthCodeFromIDToken(issuer, idTokenJwt)

            val tokenRequest = walletSvc.getTokenRequestFromAuthorizationCode(holder, authCode)

            val tokenResponse = issuerSvc.getTokenResponse(issuer, tokenRequest)

            val credRequest = walletSvc.buildCredentialRequest(holder, authRequest)

            val accessTokenJwt = SignedJWT.parse(tokenResponse.accessToken)
            issuerSvc.getNativeCredentialFromRequest(issuer, credRequest, accessTokenJwt)
        }
    }
}
