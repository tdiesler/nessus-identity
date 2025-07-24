package io.nessus.identity.service

import io.kotest.matchers.shouldBe
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class VerifyCredentialTest : AbstractServiceTest() {

    /**
     * IDToken Exchange
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#generic-flow
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
     * - Holder issues an ID Token signed by the DID's authentication key
     * - Verifier validates the IDToken
     */
    @Test
    fun idTokenExchange() {
        runBlocking {

            // Create the Verifier's OIDC context
            //
            val vctx = OIDCContext(setupWalletWithDid(Bob))

            // Create the Holders's OIDC context
            //
            val hctx = OIDCContext(setupWalletWithDid(Alice))

            // The Holder sends an AuthorizationRequest to the Verifier
            //
            val authRequest = WalletService.buildAuthorizationRequest(hctx)

            // The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
            //
            AuthService.validateAuthorizationRequest(vctx, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequest(vctx, authRequest)
            val idTokenRequestUrl = AuthService.buildIDTokenRequestUrl(vctx, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = AuthService.createIDToken(hctx, urlQueryToMap(idTokenRequestUrl))

            // Verifier validates the IDToken
            // [TODO] Validate the IDToken - AuthService.validateIDToken does actually not do that just yet
            val authCode = AuthService.validateIDToken(vctx, idTokenJwt)
            idTokenJwt.verifyJwt(hctx.didInfo) shouldBe true
        }
    }
}