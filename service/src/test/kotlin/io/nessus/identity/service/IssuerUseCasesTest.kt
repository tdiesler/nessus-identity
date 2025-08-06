package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.nessus.identity.flow.CredentialIssuanceFlow
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class IssuerUseCasesTest : AbstractServiceTest() {

    /**
     * Issue Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     *
     * Wallet Credential InTime
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#in-time
     *
     * - The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
     * - The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
     * - Holder issues an IDToken signed by the DID's authentication key
     * - Issuer validates IDToken and returns an Authorization Code
     * - Holder sends a TokenRequest to the Issuer's Token Endpoint
     * - Issuer validates the TokenRequest and responds with an AccessToken
     * - Holder sends the CredentialRequest using the AccessToken
     * - Issuer sends the requested Credential
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialInTime() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDCContext(setupWalletWithDid(Max))

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = IssuerService.createCredentialOffer(max, alice.did, types)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlow(alice, max)
            val credRes = flow.credentialFromOfferInTime(credOffer)

            // Holder validates the received Credential
            //
            val credJwt = SignedJWT.parse("${credRes.credential}")
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain ctype
            vcSubject shouldBe alice.did
            vcIssuer shouldBe max.did

            // Holder storages the Credential
            //
            WalletService.addCredential(alice, credRes)
        }
    }

    /**
     * Issue Credential Deferred
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     *
     * Wallet Credential Deferred
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#deferred
     *
     * - The Holder received a CredentialOffer and sends an AuthorizationRequest to the Issuer
     * - The Issuer's AuthService validates the AuthorizationRequest and requests proof of DID ownership
     * - Holder issues an IDToken signed by the DID's authentication key
     * - Issuer validates IDToken and returns an Authorization Code
     * - Holder sends a TokenRequest to the Issuer's Token Endpoint
     * - Issuer validates the TokenRequest and responds with an AccessToken
     * - Holder sends the CredentialRequest using the AccessToken
     * - Issuer responds with a deferred CredentialResponse that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialDeferred() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDCContext(setupWalletWithDid(Max))

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedDeferred"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = IssuerService.createCredentialOffer(max, alice.did, types)

            // Holder gets a deferred Credential from an Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlow(alice, max)
            val deferredCredRes = flow.credentialFromOfferDeferred(credOffer)

            // Holder requests the deferred Credential using the AcceptanceToken
            //
            val acceptanceTokenJwt = SignedJWT.parse(deferredCredRes.acceptanceToken)
            val credRes = IssuerService.deferredCredentialFromAcceptanceToken(max, acceptanceTokenJwt)

            // Holder validates the received Credential
            //
            val credJwt = SignedJWT.parse("${credRes.credential}")
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain ctype
            vcSubject shouldBe alice.did
            vcIssuer shouldBe max.did

            // Holder storages the Credential
            //
            WalletService.addCredential(alice, credRes)
        }
    }

    /**
     * Issue Credential PreAuthorized
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#pre-authorised-issuance
     *
     * Wallet Credential PreAuthorized
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     *
     * - The Holder received a CredentialOffer
     * - Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
     * - Issuer validates the TokenRequest and responds with an AccessToken
     * - Holder sends the CredentialRequest using the AccessToken
     * - Issuer responds with a CredentialResponse that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialPreAuthorized() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDCContext(setupWalletWithDid(Max))
            val userPin = "1234"

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = IssuerService.createCredentialOffer(max, alice.did, types, userPin)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlow(alice, max)
            val credRes = flow.credentialFromOfferPreAuthorized(credOffer, userPin)

            // Holder validates the received Credential
            //
            val credJwt = SignedJWT.parse("${credRes.credential}")
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain ctype
            vcSubject shouldBe alice.did
            vcIssuer shouldBe max.did

            // Holder storages the Credential
            //
            WalletService.addCredential(alice, credRes)
        }
    }

    /**
     * Issue Credential PreAuthorized Deferred
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#pre-authorised-issuance
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#deferred-issuance
     *
     * Wallet Credential PreAuthorized Deferred
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#pre-authorised
     * https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows#deferred
     *
     * - The Holder received a CredentialOffer
     * - Holder immediately sends a TokenRequest with the pre-authorized code to the Issuer
     * - Issuer validates the TokenRequest and responds with an AccessToken
     * - Holder sends the CredentialRequest using the AccessToken
     * - Issuer responds with a deferred CredentialResponse that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialPreAuthorizedDeferred() {
        runBlocking {

            // Create the Issuer's OIDC context (Max is the Issuer)
            //
            val max = OIDCContext(setupWalletWithDid(Max))
            val userPin = "1234"

            // Create the Holders's OIDC context (Alice is the Holder)
            //
            val alice = OIDCContext(setupWalletWithDid(Alice))

            // Issuer creates the CredentialOffer
            //
            val sub= alice.did
            val ctype = "CTWalletSamePreAuthorisedDeferred"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = IssuerService.createCredentialOffer(max, sub, types, userPin)

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlow(alice, max)
            val deferredCredRes = flow.credentialFromOfferPreAuthorizedDeferred(credOffer, userPin)

            // Pre-Authorized Holder requests the deferred Credential using the AcceptanceToken
            //
            val acceptanceTokenJwt = SignedJWT.parse(deferredCredRes.acceptanceToken)
            val credRes = IssuerService.deferredCredentialFromAcceptanceToken(max, acceptanceTokenJwt)

            // Holder validates the received Credential
            //
            val credJwt = SignedJWT.parse("${credRes.credential}")
            val vcSubject = CredentialMatcher.pathValues(credJwt, "$.vc.credentialSubject.id").first()
            val vcIssuer = CredentialMatcher.pathValues(credJwt, "$.vc.issuer").first()
            val vcTypes = CredentialMatcher.pathValues(credJwt, "$.vc.type")
            vcTypes shouldContain ctype
            vcSubject shouldBe alice.did
            vcIssuer shouldBe max.did

            // Holder storages the Credential
            //
            WalletService.addCredential(alice, credRes)
        }
    }
}