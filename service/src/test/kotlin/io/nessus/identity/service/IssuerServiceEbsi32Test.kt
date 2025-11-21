package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.random.Random

class IssuerServiceEbsi32Test : AbstractServiceTest() {

    // Generates a number between 1000 and 9999
    val userPin = Random.nextInt(1000, 10000)

    lateinit var max: OIDContext
    lateinit var alice: OIDContext

    lateinit var issuerSvc: IssuerServiceEbsi32
    lateinit var walletSvc: WalletServiceEbsi32

    @BeforeEach
    fun setUp() {
        runBlocking {
            // Create the Issuer's OIDC context (Max is the Issuer)
            max = OIDContext(login(Max).withDidInfo())

            // Create the Holders's OIDC context (Alice is the Holder)
            alice = OIDContext(loginOrRegister(Alice).withDidInfo())

            issuerSvc = IssuerService.createEbsi()
            walletSvc = WalletService.createEbsi()
        }
    }

    @Test
    fun testGetIssuerMetadata() {
        runBlocking {

            val metadataUrl = issuerSvc.getIssuerMetadataUrl(max)
            metadataUrl.shouldEndWith(".well-known/openid-credential-issuer")

            val metadata = issuerSvc.getIssuerMetadata(max)
            metadata.shouldNotBeNull()
        }
    }

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
     * - Holder sends the CredentialRequestV0 using the AccessToken
     * - Issuer sends the requested Credential
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialInTime() {
        runBlocking {

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(max, alice.did, types)
            val issuerMetadata = issuerSvc.getIssuerMetadata(max)
            max.issuerMetadata = issuerMetadata

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlowEbsi32(alice, max)
            val credRes = flow.credentialFromOfferInTime(credOffer)
            alice.issuerMetadata = issuerMetadata
            alice.credentialOffer = credOffer

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
            walletSvc.addCredential(alice, credRes)
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
     * - Holder sends the CredentialRequestV0 using the AccessToken
     * - Issuer responds with a deferred CredentialResponseV0 that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialDeferred() {
        runBlocking {

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSameAuthorisedDeferred"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(max, alice.did, types)
            val issuerMetadata = issuerSvc.getIssuerMetadata(max)
            max.issuerMetadata = issuerMetadata

            // Holder gets a deferred Credential from an Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlowEbsi32(alice, max)
            val deferredCredRes = flow.credentialFromOfferDeferred(credOffer)
            alice.issuerMetadata = issuerMetadata
            alice.credentialOffer = credOffer

            // Holder requests the deferred Credential using the AcceptanceToken
            //
            val acceptanceTokenJwt = SignedJWT.parse(deferredCredRes.acceptanceToken)
            val credRes = issuerSvc.getDeferredCredentialFromAcceptanceToken(max, acceptanceTokenJwt)

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
            walletSvc.addCredential(alice, credRes)
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
     * - Holder sends the CredentialRequestV0 using the AccessToken
     * - Issuer responds with a CredentialResponseV0 that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialPreAuthorized() {
        runBlocking {

            // Issuer creates the CredentialOffer
            //
            val ctype = "CTWalletSamePreAuthorisedInTime"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(max, alice.did, types, "$userPin")
            val issuerMetadata = issuerSvc.getIssuerMetadata(max)
            max.issuerMetadata = issuerMetadata

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlowEbsi32(alice, max)
            val credRes = flow.credentialFromOfferPreAuthorized(credOffer, "$userPin")
            alice.issuerMetadata = issuerMetadata
            alice.credentialOffer = credOffer

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
            walletSvc.addCredential(alice, credRes)
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
     * - Holder sends the CredentialRequestV0 using the AccessToken
     * - Issuer responds with a deferred CredentialResponseV0 that contains an AcceptanceToken
     * - Holder requests the Deferred Credential using the AcceptanceToken
     * - Holder validates the received Credential
     * - Holder storages the Credential
     */
    @Test
    fun issueCredentialPreAuthorizedDeferred() {
        runBlocking {

            // Issuer creates the CredentialOffer
            //
            val sub= alice.did
            val ctype = "CTWalletSamePreAuthorisedDeferred"
            val types = listOf("VerifiableCredential", ctype)
            val credOffer = issuerSvc.createCredentialOffer(max, sub, types, "$userPin")
            val issuerMetadata = issuerSvc.getIssuerMetadata(max)
            max.issuerMetadata = issuerMetadata

            // Holder gets the Credential from the Issuer based on a CredentialOffer
            //
            val flow = CredentialIssuanceFlowEbsi32(alice, max)
            val deferredCredRes = flow.credentialFromOfferPreAuthorizedDeferred(credOffer, "$userPin")
            alice.issuerMetadata = issuerMetadata
            alice.credentialOffer = credOffer

            // Pre-Authorized Holder requests the deferred Credential using the AcceptanceToken
            //
            val acceptanceTokenJwt = SignedJWT.parse(deferredCredRes.acceptanceToken)
            val credRes = issuerSvc.getDeferredCredentialFromAcceptanceToken(max, acceptanceTokenJwt)

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
            walletSvc.addCredential(alice, credRes)
        }
    }
}