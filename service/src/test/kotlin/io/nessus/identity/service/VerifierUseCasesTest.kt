package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.PresentationDefinitionBuilder
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class VerifierUseCasesTest : AbstractServiceTest() {

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
            val bob = OIDCContext(setupWalletWithDid(Bob))

            // Create the Holders's OIDC context
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            // The Holder sends an AuthorizationRequest to the Verifier
            //
            val authRequest = AuthorizationRequestBuilder(alice).build()

            // The Verifier sends an IDToken Request to the Holder (request proof of DID ownership)
            //
            AuthService.validateAuthorizationRequest(bob, authRequest)
            val idTokenRequestJwt = AuthService.buildIDTokenRequest(bob, authRequest)
            val idTokenRedirectUrl = AuthService.buildIDTokenRedirectUrl(bob, idTokenRequestJwt)

            // Holder issues an ID Token signed by the DID's authentication key
            //
            val idTokenJwt = WalletService.createIDToken(alice, urlQueryToMap(idTokenRedirectUrl))

            // Verifier validates the IDToken
            //
            AuthService.validateIDToken(bob, idTokenJwt)
            idTokenJwt.verifyJwt(alice.didInfo) shouldBe true
        }
    }

    /**
     * Verify valid Credential in Presentation
     * https://hub.ebsi.eu/conformance/build-solutions/verifier-functional-flows#verifiable-presentations
     *
     * - The Holder sends an AuthorizationRequest to the Verifier
     * - The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
     * - Holder responds with a signed VPToken that contains the VerifiablePresentation
     * - Verifier validates the VPToken
     */
    @Test
    fun validCredentialInPresentation() {
        runBlocking {

            // Create the Verifier's OIDC context (Bob is the Verifier)
            //
            val bob = OIDCContext(setupWalletWithDid(Bob))

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            val ctype = "CTWalletSameAuthorisedInTime"
            val vcFound = widWalletSvc.findCredentialsByType(alice, ctype)
            assumeTrue(vcFound.isNotEmpty(), "$ctype not found")

            // The Holder sends an AuthorizationRequest to the Verifier
            //
            val authRequest = AuthorizationRequestBuilder(alice)
                .withPresentationDefinition(
                    PresentationDefinitionBuilder()
                        .withId("same-device-authorised-in-time-credential")
                        .withInputDescriptorForType(ctype, id="inp#1")
                        .build()
                ).build()

            // The Verifier sends an VPToken Request to the Holder (request of VerifiablePresentation)
            //
            AuthService.validateAuthorizationRequest(bob, authRequest)
            val vpTokenRequestJwt = AuthService.buildVPTokenRequest(bob, authRequest)
            val vpTokenRedirectUrl = AuthService.buildVPTokenRedirectUrl(bob, vpTokenRequestJwt)
            val vpTokenRequestParams = urlQueryToMap(vpTokenRedirectUrl)
            vpTokenRequestParams["client_id"] shouldBe alice.did
            vpTokenRequestParams["response_mode"] shouldBe "direct_post"
            vpTokenRequestParams["response_type"] shouldBe "vp_token"

            // Holder responds with a signed VPToken that contains the VerifiablePresentation
            //
            val vpTokenJwt = WalletService.createVPToken(alice, authRequest)

            // Verifier validates the VPToken
            //
            val vpHolder = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.holder").first()
            vpHolder shouldBe alice.did

            val vpCred = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.verifiableCredential").first()
            val credJwt = SignedJWT.parse(vpCred)
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain ctype
            vcSubject shouldBe alice.did
        }
    }
}