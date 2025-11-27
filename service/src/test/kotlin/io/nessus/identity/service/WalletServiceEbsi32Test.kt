package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.nessus.identity.config.ConfigProvider.Alice
import org.junit.jupiter.api.Test

class WalletServiceEbsi32Test : AbstractServiceTest() {

    val walletSvc = WalletService.create()
    val issuerSvc = IssuerService.createEbsi()

    @Test
    fun getCredentialInTime() {

        // Issue Verifiable Credentials - In-time Issuance
        // https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance

        // Holder Wallet creates AuthorizationRequest
        //
        // Issuer receives AuthorizationRequest
        //  - Issuer creates IDToken Request
        //  - Holder sends IDToken Response
        // Issuer sends AuthorizationResponse (code)
        //
        // Holder sends TokenRequest
        // Issuer sends TokenResponse
        //
        // Holder sends CredentialRequest
        // Issuer sends CredentialResponse

        runBlocking {
            val holder = LoginContext.login(Alice).withDidInfo()

            val authMetadata = issuerSvc.getAuthorizationMetadata()
            val issuerMetadata = issuerSvc.getIssuerMetadata()
                .withAuthorizationMetadata(authMetadata)

            holder.createAuthContext().withIssuerMetadata(issuerMetadata)

            val credOffer = issuerSvc.createCredentialOffer("CTWalletSameAuthorisedInTime")
            log.info { jsonPretty.encodeToString(credOffer) }

            val authRequest = walletSvc.buildAuthorizationRequestFromOffer(holder, credOffer)
            log.info { jsonPretty.encodeToString(authRequest) }

        }
    }
}
